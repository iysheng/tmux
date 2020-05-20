/* $OpenBSD$ */

/*
 * Copyright (c) 2015 Nicholas Marriott <nicholas.marriott@gmail.com>
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
#include <sys/uio.h>
#include <sys/utsname.h>

#include <errno.h>
#include <event.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tmux.h"

/* 这个是进程的抽象，主要标记了进程的名字，还有该进程对应的信号的 event 实例 */
struct tmuxproc {
	const char	 *name;
	/* 这个是保存这个 tmuxproc 的退出码的？？？ */
	int		  exit;

	/* 定义的 event 实例，实际发生时会通过 proc_signal_cb
	 * 调用的函数，传递的参数就是信号的值 */
	void		(*signalcb)(int);

	struct event	  ev_sighup;
	struct event	  ev_sigchld;
	struct event	  ev_sigcont;
	struct event	  ev_sigterm;
	struct event	  ev_sigusr1;
	struct event	  ev_sigusr2;
	struct event	  ev_sigwinch;
};

/* 这个结构体是用来建立服务端和客户端通讯的联系
 * 是不是也是 child 进程和 parent 进程通讯的联系 peer
 * */
struct tmuxpeer {
	/* 表示该 tmuxpeer 属于哪个 tmuxproc */
	struct tmuxproc	*parent;

	/* 描述消息的管理实例，这个结构体包含了 fd 句柄 */
	struct imsgbuf	 ibuf;
	/* 这个 event 很重要，是 struct tmuxpeer  ！！！ */
	struct event	 event;

	int		 flags;
#define PEER_BAD 0x1

	/* 对应事件发生时执行的回调函数和对应的参数 */
	void		(*dispatchcb)(struct imsg *, void *);
	void		 *arg;
};

static int	peer_check_version(struct tmuxpeer *, struct imsg *);
static void	proc_update_event(struct tmuxpeer *);

/* struct tmux_peer 关联的 event 的回调函数，实际执行的是
 * peer 的 dispatchcb 回调函数 */
static void
proc_event_cb(__unused int fd, short events, void *arg)
{
	struct tmuxpeer	*peer = arg;
	ssize_t		 n;
	struct imsg	 imsg;

	if (!(peer->flags & PEER_BAD) && (events & EV_READ)) {
		/* 尝试从 socket pair 读取消息 */
		if (((n = imsg_read(&peer->ibuf)) == -1 && errno != EAGAIN) ||
		    n == 0) {
			/* 实际执行的是 struct tmuxpeer 的 dispatchcb 回调函数
			 * client_dispatch
			 * */
			peer->dispatchcb(NULL, peer->arg);
			return;
		}
		/* 循环处理接收到的消息 */
		for (;;) {
			/* 如果没有消息了就返回 */
			if ((n = imsg_get(&peer->ibuf, &imsg)) == -1) {
				peer->dispatchcb(NULL, peer->arg);
				return;
			}
			if (n == 0)
				break;
			log_debug("peer %p message %d", peer, imsg.hdr.type);

			if (peer_check_version(peer, &imsg) != 0) {
				if (imsg.fd != -1)
					close(imsg.fd);
				imsg_free(&imsg);
				break;
			}

			peer->dispatchcb(&imsg, peer->arg);
			imsg_free(&imsg);
		}
	}

	/* 如果是 write 事件 */
	if (events & EV_WRITE) {
		/* 这里已经将消息发送出去了！！！ */
		if (msgbuf_write(&peer->ibuf.w) <= 0 && errno != EAGAIN) {
			/* 回调函数只是做额外的动作 */
			peer->dispatchcb(NULL, peer->arg);
			return;
		}
	}

	if ((peer->flags & PEER_BAD) && peer->ibuf.w.queued == 0) {
		peer->dispatchcb(NULL, peer->arg);
		return;
	}

	proc_update_event(peer);
}

/* 这个回调函数是通过函数 proc_set_signals 
 * 初始化的 tmux_proc 的 event 的回调函数
 * */
static void
proc_signal_cb(int signo, __unused short events, void *arg)
{
	struct tmuxproc	*tp = arg;

	tp->signalcb(signo);
}

static int
peer_check_version(struct tmuxpeer *peer, struct imsg *imsg)
{
	int	version;

	version = imsg->hdr.peerid & 0xff;
	if (imsg->hdr.type != MSG_VERSION && version != PROTOCOL_VERSION) {
		log_debug("peer %p bad version %d", peer, version);

		proc_send(peer, MSG_VERSION, -1, NULL, 0);
		peer->flags |= PEER_BAD;

		return (-1);
	}
	return (0);
}

/* 更新 tmuxpeer 实例的状态，核心还是当有消息缓存在这个 tmuxpeer 时
 * 发送出去！！！，当有接收的数据在这个 tmuxpeer 时，通过回调函数处理
 * 这些消息
 * */
static void
proc_update_event(struct tmuxpeer *peer)
{
	short	events;

	/* 先删除这个 event */
	event_del(&peer->event);

	events = EV_READ;
	/* 如果有消息要发送 */
	if (peer->ibuf.w.queued > 0)
		/* 当倾听的句柄允许 write 时，就会将消息发送出去！！！
		 * 允许 write ，而不是说有数据写到对应的句柄 ！！！
		 * */
		events |= EV_WRITE;
	/* 重新初始化这个 event
	 * 如果有 queue 待发送出去的消息，当允许写时，触发 proc_event_cb 回调函数
	 * 将消息发送出去，这个 peer->ibuf.fd 还是 imsg_init(&peer->ibuf, fd)  初
	 * 始化时传递的 fd，可以通过 peer 这个回调函数的参数，找到对应的 tmuxpeer
	 * 实例，然后找到对应的缓存的消息内容
	 * */
	event_set(&peer->event, peer->ibuf.fd, events, proc_event_cb, peer);

	/* 添加这个 event，理论情况，当添加这个 event，并且已经倾听了 EV_WRITE 事件，
	 * 那么就会执行对应的回调函数， proc_event_cb，在这个回调函数，会将消息通过
	 * socket pair 将消息发送给 server， 也就是 child 进程 ！！！
	/* */
	event_add(&peer->event, NULL);
}

/* 这个函数是怎么将消息发送出去的？？？ */
int
proc_send(struct tmuxpeer *peer, enum msgtype type, int fd, const void *buf,
    size_t len)
{
	/* 消息的管理实例指针 */
	struct imsgbuf	*ibuf = &peer->ibuf;
	void		*vp = (void *)buf;
	int		 retval;

	if (peer->flags & PEER_BAD)
		return (-1);
	log_debug("sending message %d to peer %p (%zu bytes)", type, peer, len);

	/* 构造消息，这个 -1 很特殊？？？
	 * 关联这个 fd 到 ibuf
	 * PROROCOL_VERSION 是 imsg_compose 的 peerid
	 * pid = -1
	 * fd 是句柄，发送认证消息的时候，句柄是 -1
	 * vp 是消息内容
	 * len 是消息的长度
	 * */
	/* 将需要发送的消息，包括消息类型，添加到 struct imsgbuf ibuf 通过
	 * struct msgbuf w 管理的 struct ibuf tailqueue */
	retval = imsg_compose(ibuf, type, PROTOCOL_VERSION, -1, fd, vp, len);
	if (retval != 1)
		return (-1);
	/* 是在这里将消息发送出去的，libevent 的 write 事件就是在允许 write 的时候
	 * 将数据发送出去 */
	proc_update_event(peer);
	return (0);
}

/* 创建一个 tmuxproc 实例，名字初始化为 name 指向的字符串 */
struct tmuxproc *
proc_start(const char *name)
{
	struct tmuxproc	*tp;
	struct utsname	 u;

	/* 尝试记录日志，如果没有 -v 选项，这里可以认为是空 */
	/* 创建 log 文件 */
	log_open(name);
	/* 修改线程的名字 */
	setproctitle("%s (%s)", name, socket_path);

	if (uname(&u) < 0)
		memset(&u, 0, sizeof u);

	log_debug("%s started (%ld): version %s, socket %s, protocol %d", name,
	    (long)getpid(), getversion(), socket_path, PROTOCOL_VERSION);
	log_debug("on %s %s %s; libevent %s (%s)", u.sysname, u.release,
	    u.version, event_get_version(), event_get_method());

	/* 申请一个 tmuxproc 结构体实例，将首地址保存到 tp 指针 */
	tp = xcalloc(1, sizeof *tp);
	tp->name = xstrdup(name);

	return (tp);
}

void
proc_loop(struct tmuxproc *tp, int (*loopcb)(void))
{
	log_debug("%s loop enter", tp->name);
	do
		event_loop(EVLOOP_ONCE);
	while (!tp->exit && (loopcb == NULL || !loopcb ()));
	log_debug("%s loop exit", tp->name);
}

void
proc_exit(struct tmuxproc *tp)
{
	tp->exit = 1;
}

/* 关联 tmuxproc 的回调函数 signalcb
 * 注册 tmuxproc 涉及到的 event 事件的回调函数
 * 总结：初始化 tmuxproc 的管理的 event 事件的回调函数为 signalcb
 * */
void
proc_set_signals(struct tmuxproc *tp, void (*signalcb)(int))
{
	struct sigaction	sa;

	/* 关联这个 tmuxproc 实例的 event 信号事件回调函数 */
	tp->signalcb = signalcb;

	memset(&sa, 0, sizeof sa);
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_IGN;

	/* 忽略掉这三个信号 */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGTSTP, &sa, NULL);

	/* 注册 libevent 对应事件的回调函数 */
	signal_set(&tp->ev_sighup, SIGHUP, proc_signal_cb, tp);
	signal_add(&tp->ev_sighup, NULL);
	signal_set(&tp->ev_sigchld, SIGCHLD, proc_signal_cb, tp);
	signal_add(&tp->ev_sigchld, NULL);
	signal_set(&tp->ev_sigcont, SIGCONT, proc_signal_cb, tp);
	signal_add(&tp->ev_sigcont, NULL);
	signal_set(&tp->ev_sigterm, SIGTERM, proc_signal_cb, tp);
	signal_add(&tp->ev_sigterm, NULL);
	signal_set(&tp->ev_sigusr1, SIGUSR1, proc_signal_cb, tp);
	signal_add(&tp->ev_sigusr1, NULL);
	signal_set(&tp->ev_sigusr2, SIGUSR2, proc_signal_cb, tp);
	signal_add(&tp->ev_sigusr2, NULL);
	signal_set(&tp->ev_sigwinch, SIGWINCH, proc_signal_cb, tp);
	signal_add(&tp->ev_sigwinch, NULL);
}

/* 修改一些信号为默认的处理函数 */
void
proc_clear_signals(struct tmuxproc *tp, int defaults)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof sa);
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_DFL;

	/* 修改 SIGINT、SIGPIPE 和 SIGTSTP 信号默认处理函数 */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGTSTP, &sa, NULL);

	/* 删除指定信号的 event 回调函数 */
	signal_del(&tp->ev_sighup);
	signal_del(&tp->ev_sigchld);
	signal_del(&tp->ev_sigcont);
	signal_del(&tp->ev_sigterm);
	signal_del(&tp->ev_sigusr1);
	signal_del(&tp->ev_sigusr2);
	signal_del(&tp->ev_sigwinch);

	/* 如果 defaults 为真，那么设置指定信号默认处理函数 */
	if (defaults) {
		sigaction(SIGHUP, &sa, NULL);
		sigaction(SIGCHLD, &sa, NULL);
		sigaction(SIGCONT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGUSR1, &sa, NULL);
		sigaction(SIGUSR2, &sa, NULL);
		sigaction(SIGWINCH, &sa, NULL);
	}
}

/* 根据 struct tmuxproc 实例，创建一个 tmuxpeer 实例 */
struct tmuxpeer *
proc_add_peer(struct tmuxproc *tp, int fd,
    void (*dispatchcb)(struct imsg *, void *), void *arg)
{
	struct tmuxpeer	*peer;

	peer = xcalloc(1, sizeof *peer);
	/* 给这个 tmuxpeer 的 parent 成员赋值对应的 tmuxproc 实例指针
	 * 表示该 tmuxpeer 属于哪个 tmuxproc
	 * 分析单个 tmux 启动只会创建两个 tmuxproc， server 和 client
	 * */
	peer->parent = tp;

	/* 有事件发生时，执行的函数和参数 */
	peer->dispatchcb = dispatchcb;
	peer->arg = arg;

	/* 初始化句柄给读和写的管理结构体，并且关联 fd 到 struct tmuxpeer 的 ibuf
	 * 管理实例和对应的写缓冲区的管理结构体
	 * */
	imsg_init(&peer->ibuf, fd);
	/* 初始化 struct tmuxpeer 的 event，关联的是 fd，回调函数是 proc_event_cb */
	event_set(&peer->event, fd, EV_READ, proc_event_cb, peer);

	log_debug("add peer %p: %d (%p)", peer, fd, arg);

	/* tmuxpeer 完成了初始化，更新 tmuxpeer 关联的 fd 的事件状态
	 * 当有消息接收时处理这些消息
	 * 当有消息缓存待发送时，将这些消息发送出去
	 * */
	proc_update_event(peer);
	return (peer);
}

void
proc_remove_peer(struct tmuxpeer *peer)
{
	log_debug("remove peer %p", peer);

	event_del(&peer->event);
	imsg_clear(&peer->ibuf);

	close(peer->ibuf.fd);
	free(peer);
}

void
proc_kill_peer(struct tmuxpeer *peer)
{
	peer->flags |= PEER_BAD;
}

void
proc_toggle_log(struct tmuxproc *tp)
{
	log_toggle(tp->name);
}
