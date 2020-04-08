/* $OpenBSD$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicholas.marriott@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "tmux.h"

/*
 * Main server functions.
 */

/* 全局的 clients tail queue 类型
 * server 通过 server_client_create 函数创建的
 * 所有 client 实例都会在这里管理
 * */
struct clients		 clients;

/* 保存作为服务端的 tmuxproc 实例指针 */
struct tmuxproc		*server_proc;
/* 保存 server 创建的 unix socket 句柄，该句柄在服务端，监听 client 的链接
 * 绑定的是路径 socket_path，一般地路径是 /tmp/tmux-1000/default
 * */
static int		 server_fd = -1;
static int		 server_exit;
/* 倾听 server_fd 对应的 socket 的 accept 事件 */
static struct event	 server_ev_accept;

struct cmd_find_state	 marked_pane;

static int	server_loop(void);
static void	server_send_exit(void);
static void	server_accept(int, short, void *);
static void	server_signal(int);
static void	server_child_signal(void);
static void	server_child_exited(pid_t, int);
static void	server_child_stopped(pid_t, int);

/* Set marked pane. */
void
server_set_marked(struct session *s, struct winlink *wl, struct window_pane *wp)
{
	cmd_find_clear_state(&marked_pane, 0);
	marked_pane.s = s;
	marked_pane.wl = wl;
	marked_pane.w = wl->window;
	marked_pane.wp = wp;
}

/* Clear marked pane. */
void
server_clear_marked(void)
{
	cmd_find_clear_state(&marked_pane, 0);
}

/* Is this the marked pane? */
int
server_is_marked(struct session *s, struct winlink *wl, struct window_pane *wp)
{
	if (s == NULL || wl == NULL || wp == NULL)
		return (0);
	if (marked_pane.s != s || marked_pane.wl != wl)
		return (0);
	if (marked_pane.wp != wp)
		return (0);
	return (server_check_marked());
}

/* Check if the marked pane is still valid. */
int
server_check_marked(void)
{
	return (cmd_find_valid_state(&marked_pane));
}

/* Create server socket. */
/* 服务端创建 socket 绑定 socket_path 文件，
 * 之后才可以直接和这个 socket 通信，一般的地址是 /tmp/tmux-$(uid)/default
 * 创建服务端的 socket，返回创建的 socket 句柄 */
static int
server_create_socket(char **cause)
{
	struct sockaddr_un	sa;
	size_t			size;
	mode_t			mask;
	int			fd, saved_errno;

	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	size = strlcpy(sa.sun_path, socket_path, sizeof sa.sun_path);
	if (size >= sizeof sa.sun_path) {
		errno = ENAMETOOLONG;
		goto fail;
	}
	unlink(sa.sun_path);

	/* 创建服务端的 socket */
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		goto fail;

	mask = umask(S_IXUSR|S_IXGRP|S_IRWXO);
	/* 绑定服务端的 socket 到指定的文件 */
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == -1) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		goto fail;
	}
	umask(mask);

	/* 开始倾听 client 端的链接 */
	if (listen(fd, 128) == -1) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		goto fail;
	}
	/* 设置 socket 为非阻塞态 */
	setblocking(fd, 0);

	return (fd);

fail:
	if (cause != NULL) {
		xasprintf(cause, "error creating %s (%s)", socket_path,
		    strerror(errno));
	}
	return (-1);
}

/* Fork new server. */
/* 在这里会 fork child 进程，parent 进程作为 client ，child 进程作为 server */
int
server_start(struct tmuxproc *client, struct event_base *base, int lockfd,
    char *lockfile)
{
	int		 pair[2];
	sigset_t	 set, oldset;
	struct client	*c;
	char		*cause = NULL;

	/* 创建一对链接的 socket，用来 child 进程和 parent 进程通讯
	 * parent 进程使用的是 pair[0]
	 * child 进程使用的是 pair[1]
	 * */
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pair) != 0)
		fatal("socketpair failed");

	sigfillset(&set);
	/* 阻塞所有的信号 */
	sigprocmask(SIG_BLOCK, &set, &oldset);
	/* 创建新的进程 */
	switch (fork()) {
	case -1:
		fatal("fork failed");
	case 0:
		/* child 进程，跳出 switch，继续执行 */
		break;
	default:
		/* parent 进程，恢复所有的信号，直接返回可以和 child 进程通讯的 socket 句柄 */
		sigprocmask(SIG_SETMASK, &oldset, NULL);
		/* 关闭 pair[1] socket 句柄 */
		close(pair[1]);
		/* parent 返回 pair[0] 句柄，可以通过该句柄和 child 进程通讯 */
		return (pair[0]);
	}
	/* child 进程，关闭 pair[0] socket 句柄，只用 pair[1] 句柄
	 * 就可以和 parent 进程通讯 */
	close(pair[0]);
	/* 新 fork 出来的 child 进程后台执行，作为守护进程
	 * arg1 = 1，
	 * arg2 = 0，重定向标准输入、输出、错误输出到 /dev/null
	 * */
	if (daemon(1, 0) != 0)
		fatal("daemon failed");
	/* 修改 child 进程也就是 server 一些信号 SIGINT, SIGPIPE, SIGTSTP 为默认的处理函数
	 * 因为是 fork 的进程，继承的是 parent 的内存空间数据，需要删除 parent 进程关联的
	 * 一些 event 事件，如果 default 参数为真，那么会重新修改那些 event 关联的信号为
	 * 默认的处理进程
	 * */
	proc_clear_signals(client, 0);
	/* fork 进程后，需要在 child 进程重新初始化 event_base */
	if (event_reinit(base) != 0)
		fatalx("event_reinit failed");
	/* 修改进程的名字，申请一个 tmuxproc 实例内存空间
	 * parent 进程对应的是 client 的 tmuxproc 实例，也就是全局变量 client_proc
	 * 与之对应的 child 进程对应的是 server 的 tmuxproc 实例，也就是全局变量 server_proc
	 * */
	server_proc = proc_start("server");
	/* 修改一些信号的处理函数为 server_signal
	 * 同时忽略掉三个信号 SIGINT, SIGPIPE, SIGTSTP
	 * 修改 server 端的回调函数为 server_signal
	 * */
	proc_set_signals(server_proc, server_signal);
	/* 恢复所有的信号状态 */
	sigprocmask(SIG_SETMASK, &oldset, NULL);

	/* 如果没有开启 -v 选项，这里为假 */
	if (log_get_level() > 1)
		tty_create_log();
	if (pledge("stdio rpath wpath cpath fattr unix getpw recvfd proc exec "
	    "tty ps", NULL) != 0)
		fatal("pledge failed");

	/* 初始化 windows 类型的 rbtree 根节点 */
	RB_INIT(&windows);
	/* 初始化 pane 类型的 rbtree 根节点 */
	RB_INIT(&all_window_panes);
	/* 初始化 clients 是 tailq */
	TAILQ_INIT(&clients);
	/* 初始化 session 类型的 rbtree 根节点 */
	RB_INIT(&sessions);
	/* 按键绑定初始化，追加到全局的 tail queue 类型 struct cmdq_list global_queue */
	key_bindings_init();

	/* 保存启动时间信息 */
	gettimeofday(&start_time, NULL);

	/* 根据之前初始化的全局变量 socket_path 保存的 socket 的路径，
	 * 创建 unix socket ！！！ */
	server_fd = server_create_socket(&cause);
	if (server_fd != -1)
		/* 修改了 socket_path 文件的权限 */
		server_update_socket();
	/* 倾听 pair[1] 的读 event ，即 parent 进程发送给 child 进程的消息
	 * 这是创建的第一个 client ！！！ 倾听的是和 parent 进程作为 client 端
	 * 的 socket pair，在创建这个 client 后，已经添加到全局变量 clients 管理
	 * 的 tailq 了
	 * server 在创建 client 的同时，会同步创建一个 tmuxpeer，将这个 tmuxpeer 关联
	 * 到 client 实例，每创建一个 client 都会初始化一次 statusline
	 * */
	c = server_client_create(pair[1]);

	/* 关闭并删除锁文件 */
	if (lockfd >= 0) {
		unlink(lockfile);
		free(lockfile);
		close(lockfd);
	}

	/* 如果绑定本地的 server socket 出错了 */
	if (cause != NULL) {
		cmdq_append(c, cmdq_get_error(cause));
		free(cause);
		c->flags |= CLIENT_EXIT;
	}

	/* 添加 accept event 的回调函数 server_accept
	 * 这里倾听的是根据路径 /tmp/tmux-1000/default 创建的 UNIX socket
	 * */
	server_add_accept(0);
	/* 循环 event 倾听，这个循环不能退出
	 * 目前位置，系统存在两个 struct tmux_proc 分别是 client 和  server
	 * 对应的存在两个 struct tmux_peer ，分别是 client 和 server ，
	 * 这两个 tmux_peer 关联的 fd 是 socketpair 创建出来的两个 socket
	 * 还有一个 server_ev_accept event，倾听的是 server_fd 对应的是 UNIX socket，绑定
	 * 的路径是 /tmp/tmux-1000/default
	 * */
	/* 有任何 event 事件发生，都会执行 server_loop 回调函数
	 * 正常情况下，server 进程会一直循环在这个函数！！！
	 * */
	proc_loop(server_proc, server_loop);

	job_kill_all();
	status_prompt_save_history();

	exit(0);
}

/* Server loop callback. */
/* 服务端的循环回调函数
 * 目前知道的服务端循环倾听两个句柄
 * 1. 服务端创建的 socket，等待 client 的链接
 * 2. child 进程和 parent 进程通讯的 socket peer，child 使用的是 pair[1]，parent 使用的是 pair[0]
 * */
static int
server_loop(void)
{
	struct client	*c;
	u_int		 items;

	do {
		/* 查找 key bind 命令 */
		items = cmdq_next(NULL);
		/* 遍历所有的 client */
		TAILQ_FOREACH(c, &clients, entry) {
			if (c->flags & CLIENT_IDENTIFIED)
				items += cmdq_next(c);
		}
	} while (items != 0);

	server_client_loop();

	if (!options_get_number(global_options, "exit-empty") && !server_exit)
		return (0);

	if (!options_get_number(global_options, "exit-unattached")) {
		if (!RB_EMPTY(&sessions))
			return (0);
	}

	TAILQ_FOREACH(c, &clients, entry) {
		if (c->session != NULL)
			return (0);
	}

	/*
	 * No attached clients therefore want to exit - flush any waiting
	 * clients but don't actually exit until they've gone.
	 */
	cmd_wait_for_flush();
	if (!TAILQ_EMPTY(&clients))
		return (0);

	if (job_still_running())
		return (0);

	return (1);
}

/* Exit the server by killing all clients and windows. */
static void
server_send_exit(void)
{
	struct client	*c, *c1;
	struct session	*s, *s1;

	cmd_wait_for_flush();

	TAILQ_FOREACH_SAFE(c, &clients, entry, c1) {
		if (c->flags & CLIENT_SUSPENDED)
			server_client_lost(c);
		else {
			if (c->flags & CLIENT_ATTACHED)
				notify_client("client-detached", c);
			proc_send(c->peer, MSG_SHUTDOWN, -1, NULL, 0);
		}
		c->session = NULL;
	}

	RB_FOREACH_SAFE(s, sessions, &sessions, s1)
		session_destroy(s, 1, __func__);
}

/* Update socket execute permissions based on whether sessions are attached. */
/* 根据是否有 session 联系到了 server，来更新 socket 的可执行权限 */
void
server_update_socket(void)
{
	struct session	*s;
	static int	 last = -1;
	int		 n, mode;
	struct stat      sb;

	n = 0;
	/* 循环变量所有的 sessions */
	RB_FOREACH(s, sessions, &sessions) {
		if (s->attached != 0) {
			n++;
			break;
		}
	}

	if (n != last) {
		last = n;

		if (stat(socket_path, &sb) != 0)
			return;
		mode = sb.st_mode & ACCESSPERMS;
		if (n != 0) {
			if (mode & S_IRUSR)
				mode |= S_IXUSR;
			if (mode & S_IRGRP)
				mode |= S_IXGRP;
			if (mode & S_IROTH)
				mode |= S_IXOTH;
		} else
			/* 取消所有的不可以执行权限 */
			mode &= ~(S_IXUSR|S_IXGRP|S_IXOTH);
		/* 修改 socket 的权限 */
		chmod(socket_path, mode);
	}
}

/* Callback for server socket. */
/* 服务端 socket accept 事件的回调函数
 * 倾听的 fd 绑定的是 UNIX socket，路径是 /tmp/tmux-1000/default
 * */
static void
server_accept(int fd, short events, __unused void *data)
{
	struct sockaddr_storage	sa;
	socklen_t		slen = sizeof sa;
	int			newfd;

	server_add_accept(0);
	if (!(events & EV_READ))
		return;

	/* 接受 client 的连接请求，创建一个信达 socket */
	newfd = accept(fd, (struct sockaddr *) &sa, &slen);
	if (newfd == -1) {
		if (errno == EAGAIN || errno == EINTR || errno == ECONNABORTED)
			return;
		if (errno == ENFILE || errno == EMFILE) {
			/* Delete and don't try again for 1 second. */
			server_add_accept(1);
			return;
		}
		fatal("accept failed");
	}
	if (server_exit) {
		close(newfd);
		return;
	}
	/* 根据传入的 newfd 创建一个新的 client */
	server_client_create(newfd);
}

/*
 * Add accept event. If timeout is nonzero, add as a timeout instead of a read
 * event - used to backoff when running out of file descriptors.
 */
/*
 * 添加 accept event， 如果 timeout 不为 0, 添加一个 timeout event
 * 一般地， timeout 都是 0
 * */
void
server_add_accept(int timeout)
{
	struct timeval tv = { timeout, 0 };

	if (server_fd == -1)
		return;

	/* 初始化一个 accept event */
	if (event_initialized(&server_ev_accept))
		event_del(&server_ev_accept);

	if (timeout == 0) {
		/* 初始化这个事件的 accept 回调函数为 server_accept
		 * 并且初始化这个 event 关联到默认的 event_base，就是当前进程唯一
		 * 的 event_base
		 * */
		event_set(&server_ev_accept, server_fd, EV_READ, server_accept,
		    NULL);
		/* 添加这个 event */
		event_add(&server_ev_accept, NULL);
	} else {
		event_set(&server_ev_accept, server_fd, EV_TIMEOUT,
		    server_accept, NULL);
		event_add(&server_ev_accept, &tv);
	}
}

/* Signal handler. */
/* 服务端倾听 event 事件的回调函数
 * 与之对应的作为 client 的 event 事件的回调函数是 client_signal */
static void
server_signal(int sig)
{
	int	fd;

	log_debug("%s: %s", __func__, strsignal(sig));
	switch (sig) {
	case SIGTERM:
		server_exit = 1;
		server_send_exit();
		break;
	case SIGCHLD:
		server_child_signal();
		break;
	/* 当客户端发送了 SIGUSR1 信号，触发服务端重新创建 server_socket 句柄，倾听 /tmp/tmux-$(uid)/default
	 * 本机 socket，来实现进程间通讯
	 * */
	case SIGUSR1:
		event_del(&server_ev_accept);
		fd = server_create_socket(NULL);
		/* 如果成功创建了倾听 client 端连接的 socket，那么使用这个新的 socket 句柄
		 * 替换之前初始化时创建的 socket pair ？？？
		 * */
		if (fd != -1) {
			close(server_fd);
			server_fd = fd;
			server_update_socket();
		}
		server_add_accept(0);
		break;
	case SIGUSR2:
		proc_toggle_log(server_proc);
		break;
	}
}

/* Handle SIGCHLD. */
static void
server_child_signal(void)
{
	int	 status;
	pid_t	 pid;

	for (;;) {
		switch (pid = waitpid(WAIT_ANY, &status, WNOHANG|WUNTRACED)) {
		case -1:
			if (errno == ECHILD)
				return;
			fatal("waitpid failed");
		case 0:
			return;
		}
		if (WIFSTOPPED(status))
			server_child_stopped(pid, status);
		else if (WIFEXITED(status) || WIFSIGNALED(status))
			server_child_exited(pid, status);
	}
}

/* Handle exited children. */
static void
server_child_exited(pid_t pid, int status)
{
	struct window		*w, *w1;
	struct window_pane	*wp;

	RB_FOREACH_SAFE(w, windows, &windows, w1) {
		TAILQ_FOREACH(wp, &w->panes, entry) {
			if (wp->pid == pid) {
				wp->status = status;
				wp->flags |= PANE_STATUSREADY;

				log_debug("%%%u exited", wp->id);
				wp->flags |= PANE_EXITED;

				if (window_pane_destroy_ready(wp))
					server_destroy_pane(wp, 1);
				break;
			}
		}
	}
	job_check_died(pid, status);
}

/* Handle stopped children. */
static void
server_child_stopped(pid_t pid, int status)
{
	struct window		*w;
	struct window_pane	*wp;

	if (WSTOPSIG(status) == SIGTTIN || WSTOPSIG(status) == SIGTTOU)
		return;

	RB_FOREACH(w, windows, &windows) {
		TAILQ_FOREACH(wp, &w->panes, entry) {
			if (wp->pid == pid) {
				if (killpg(pid, SIGCONT) != 0)
					kill(pid, SIGCONT);
			}
		}
	}
}
