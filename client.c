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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/file.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tmux.h"

static struct tmuxproc    *client_proc;
/* 客户端 peer，这个是关联的 socket_pair 句柄 */
static struct tmuxpeer    *client_peer;
/* 保存的是 main 函数传递的初始化 flag，一般情况下，该值只是置位了 CLIENT_UTF8  */
static int         client_flags;
static enum {
    CLIENT_EXIT_NONE,
    CLIENT_EXIT_DETACHED,
    CLIENT_EXIT_DETACHED_HUP,
    CLIENT_EXIT_LOST_TTY,
    CLIENT_EXIT_TERMINATED,
    CLIENT_EXIT_LOST_SERVER,
    CLIENT_EXIT_EXITED,
    CLIENT_EXIT_SERVER_EXITED,
} client_exitreason = CLIENT_EXIT_NONE;
static int         client_exitflag;
static int         client_exitval;
static enum msgtype     client_exittype;
static const char    *client_exitsession;
static const char    *client_execshell;
static const char    *client_execcmd;
static int         client_attached;
static struct client_files client_files = RB_INITIALIZER(&client_files);

static __dead void     client_exec(const char *,const char *);
static int         client_get_lock(char *);
static int         client_connect(struct event_base *, const char *, int);
static void         client_send_identify(const char *, const char *);
static void         client_signal(int);
static void         client_dispatch(struct imsg *, void *);
static void         client_dispatch_attached(struct imsg *);
static void         client_dispatch_wait(struct imsg *);
static const char    *client_exit_message(void);

/*
 * Get server create lock. If already held then server start is happening in
 * another client, so block until the lock is released and return -2 to
 * retry. Return -1 on failure to continue and start the server anyway.
 */
/* 获取创建服务器的锁文件 */
static int
client_get_lock(char *lockfile)
{
    int lockfd;

    log_debug("lock file is %s", lockfile);

    /* 创建这把锁文件 */
    if ((lockfd = open(lockfile, O_WRONLY|O_CREAT, 0600)) == -1) {
        log_debug("open failed: %s", strerror(errno));
        return (-1);
    }

    /* 放置一个非阻塞的互斥锁，表示同一时刻只有一个进程可以获取对应的 lockfd 句柄 */
    if (flock(lockfd, LOCK_EX|LOCK_NB) == -1) {
        log_debug("flock failed: %s", strerror(errno));
        if (errno != EAGAIN)
            return (lockfd);
        /* 如果是被信号打断的，那么继续尝试 */
        while (flock(lockfd, LOCK_EX) == -1 && errno == EINTR)
            /* nothing */;
        close(lockfd);
        return (-2);
    }
    log_debug("flock succeeded");

    return (lockfd);
}

/* Connect client to server. */
/* 连接客户端到服务器 */
static int
client_connect(struct event_base *base, const char *path, int start_server)
{
    /* 定义一个 local socket 实例 */
    struct sockaddr_un    sa;
    size_t            size;
    int            fd, lockfd = -1, locked = 0;
    char               *lockfile = NULL;

    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    /* 使用之前定义的 socket 路径，赋值给 sa
     * 猜测是只要，指定文件的路径存在，那么后续就会 connect 成功
     * */
    size = strlcpy(sa.sun_path, path, sizeof sa.sun_path);
    if (size >= sizeof sa.sun_path) {
        errno = ENAMETOOLONG;
        return (-1);
    }
    log_debug("socket is %s", path);

retry:
    /* 创建一个本地的面向流的 socket */
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        return (-1);

    log_debug("trying connect");
    /* 尝试链接本地服务端 socket，需要指定的文件存在，并且绑定了一个 server 端的 socket 才会
     * connect 成功,
     * 所以第一次 tmux 启动返回的总是 -1 ，因为这个作为 server 的 socket 还不存在，只有当 tmux
	 * 启动后，再次执行 tmux，这时候才会 connect 成功
	 * 只有第一次启动 tmux 时，可以和服务进程通讯的句柄是执行 server_start 函数创建出来的 socketpair，
	 * 其他的都是通过 connect 链接到 AF_UNIX 类型的 socket 
     * */
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == -1) {
        log_debug("connect failed: %s", strerror(errno));
        /* 第一次这个时候应该返回 ENOENT */
        if (errno != ECONNREFUSED && errno != ENOENT)
            goto failed;
        if (!start_server)
            goto failed;
        /* 因为连接未成功，关闭这个句柄 fd */
        close(fd);

        /* 初始化 locked == 0 */
        if (!locked) {
            /* lockfile 的路径默认是 /tmp/tmux-1000/default.lock */
            xasprintf(&lockfile, "%s.lock", path);
            /* 获取这个 socket 的锁 */
            if ((lockfd = client_get_lock(lockfile)) < 0) {
                log_debug("didn't get lock (%d)", lockfd);

                free(lockfile);
                lockfile = NULL;

                if (lockfd == -2)
                    goto retry;
            }
            log_debug("got lock (%d)", lockfd);

            /*
             * Always retry at least once, even if we got the lock,
             * because another client could have taken the lock,
             * started the server and released the lock between our
             * connect() and flock().
             */
            /* 即使拿到了这把 flock，至少也要 retry 1 次
             * 标记拿到了这把文件锁
             * */
            locked = 1;
            goto retry;
        }

        /* 如果拿到了这把锁，尝试删除这个 path 文件，这个 path 默认是
         * /tmp/tmux-1000/default 文件，本地作为服务端的 AF_UNIX family 的 socket
         * */
        if (lockfd >= 0 && unlink(path) != 0 && errno != ENOENT) {
            free(lockfile);
            close(lockfd);
            return (-1);
        }
        /* 第一次 connect 的时候，因为没有对应的 server bind 这个 AF_UNIX 的 socket，
         * 所以不会成功，这个 fd 对应的是创建的 socket pair 的 pari[0] 准备启动 server
         * lockfd 是 flock 锁的句柄
         * lockfile 是 flock 锁对应的文件路径
         * 返回的 fd 是 parent 进程可以和 child 进程通信的句柄
         * 这个函数只会执行一次，即在第一次 tmux 启动的时候
         * */
        fd = server_start(client_proc, base, lockfd, lockfile);
    }

    /* 因为已经拿到了这个文件锁，删除相关的锁文件 */
    if (locked && lockfd >= 0) {
        free(lockfile);
        close(lockfd);
    }
    /* parent 进程的 fd 是和 child 进程通讯的 socket pair[0] 句柄
     * 设置该 socket 为非阻塞态 */
    setblocking(fd, 0);
    return (fd);

failed:
    if (locked) {
        free(lockfile);
        close(lockfd);
    }
    close(fd);
    return (-1);
}

/* Get exit string from reason number. */
const char *
client_exit_message(void)
{
    static char msg[256];

    switch (client_exitreason) {
    case CLIENT_EXIT_NONE:
        break;
    case CLIENT_EXIT_DETACHED:
        if (client_exitsession != NULL) {
            xsnprintf(msg, sizeof msg, "detached "
                "(from session %s)", client_exitsession);
            return (msg);
        }
        return ("detached");
    case CLIENT_EXIT_DETACHED_HUP:
        if (client_exitsession != NULL) {
            xsnprintf(msg, sizeof msg, "detached and SIGHUP "
                "(from session %s)", client_exitsession);
            return (msg);
        }
        return ("detached and SIGHUP");
    case CLIENT_EXIT_LOST_TTY:
        return ("lost tty");
    case CLIENT_EXIT_TERMINATED:
        return ("terminated");
    case CLIENT_EXIT_LOST_SERVER:
        return ("server exited unexpectedly");
    case CLIENT_EXIT_EXITED:
        return ("exited");
    case CLIENT_EXIT_SERVER_EXITED:
        return ("server exited");
    }
    return ("unknown reason");
}

/* Exit if all streams flushed. */
static void
client_exit(void)
{
    struct client_file    *cf;
    size_t              left;
    int             waiting = 0;

    RB_FOREACH (cf, client_files, &client_files) {
        if (cf->event == NULL)
            continue;
        left = EVBUFFER_LENGTH(cf->event->output);
        if (left != 0) {
            waiting++;
            log_debug("file %u %zu bytes left", cf->stream, left);
        }
    }
    if (waiting == 0)
        proc_exit(client_proc);
}

/* Client main loop. */
int
client_main(struct event_base *base, int argc, char **argv, int flags)
{
    struct cmd_parse_result    *pr;
    struct cmd        *cmd;
    struct msg_command    *data;
    int             cmdflags, fd, i;
    const char        *ttynam, *cwd;
    pid_t             ppid;
    enum msgtype         msg;
    struct termios         tio, saved_tio;
    size_t             size;

    /* Ignore SIGCHLD now or daemon() in the server will leave a zombie. */
    /* 现在忽视掉 SIGCHLD 信号，否则会将服务端的守护进程会被置为僵尸态 */
    signal(SIGCHLD, SIG_IGN);

    /* Save the flags. */
    /* 保存 main 函数传递的 flags 到全局变量 */
    client_flags = flags;

    /* Set up the initial command. */
    /* 建立初始化的命令 */
    cmdflags = 0;
    if (shell_command != NULL) {
        msg = MSG_SHELL;
        cmdflags = CMD_STARTSERVER;
    } else if (argc == 0) {
        /* 一般情况会走到这里 */
        msg = MSG_COMMAND;
        cmdflags = CMD_STARTSERVER;
    } else {
        msg = MSG_COMMAND;

        /*
         * It sucks parsing the command string twice (in client and
         * later in server) but it is necessary to get the start server
         * flag.
         */
        pr = cmd_parse_from_arguments(argc, argv, NULL);
        if (pr->status == CMD_PARSE_SUCCESS) {
            TAILQ_FOREACH(cmd, &pr->cmdlist->list, qentry) {
                if (cmd->entry->flags & CMD_STARTSERVER)
                    cmdflags |= CMD_STARTSERVER;
            }
            cmd_list_free(pr->cmdlist);
        } else
            free(pr->error);
    }

    /* Create client process structure (starts logging). */
    /* 创建一个 tmuxproc 实例，名字命名为 client
     * 同时修改这个线程的名字为 "client"
     * 这个线程是 parent 进程
     * */
    client_proc = proc_start("client");
    /* 设置这个线程处理信号 event 事件的回调函数 proc_signal_cb
     * 基于 libevent 框架，实际是注册对应信号的 event 的回调函数为 client_signal
     * */
    proc_set_signals(client_proc, client_signal);

    /* Initialize the client socket and start the server. */
    /* parent 进程作为 client，返回的是一个句柄是可以和守护进程（服务进程）通讯的 pair[0] */
    fd = client_connect(base, socket_path, cmdflags & CMD_STARTSERVER);
    if (fd == -1) {
        if (errno == ECONNREFUSED) {
            fprintf(stderr, "no server running on %s\n",
                socket_path);
        } else {
            fprintf(stderr, "error connecting to %s (%s)\n",
                socket_path, strerror(errno));
        }
        return (1);
    }
    /* 添加这个和 server 端通讯的 socket 句柄的回调函数 client_dispatch ！！！
     * 返回一个 tmuxpeer 实例指针，通过这个指针，可以找到对应的 fd 句柄
     * 通过发消息给该句柄，可以发送消息给 server，绑定这个 client 有 event
     * 事件发生时，回调函数 client_dispatch，这个 client 是 tmux 启动唯一通过
	 * socket_pair 可以和守护进程通讯的句柄
     * */
    client_peer = proc_add_peer(client_proc, fd, client_dispatch, NULL);

    /* Save these before pledge(). */
    /* 获取当前目录的名字保存到 cwd 字符串 */
    if ((cwd = find_cwd()) == NULL && (cwd = find_home()) == NULL)
        cwd = "/";
    /* 获取当前进程标准输入使用的终端名字，测试打印的格式是 /dev/pts/[number] 数字
     * 这个 number 会随着打开终端的个数增加而增加
     * ptmx, pts - pseudoterminal master and slave，/deb/ptmx 是一个字符设备，通常用来
     * 创建伪终端的 master 和 slave 对，进程每打开一次 /dev/ptmx，都会获取一个独立的
     * ptm 的描述符，同时也会在 /dev/pts 目录创建一个对应的 pts 设备，可以将返回
     * 的 ptm 描述符作为参数传递给函数 ptsname，获取对应的 pts 设备名字
     * */
    if ((ttynam = ttyname(STDIN_FILENO)) == NULL)
        ttynam = "";

    /*
     * Drop privileges for client. "proc exec" is needed for -c and for
     * locking (which uses system(3)).
     *
     * "tty" is needed to restore termios(4) and also for some reason -CC
     * does not work properly without it (input is not recognised).
     *
     * "sendfd" is dropped later in client_dispatch_wait().
     */
    if (pledge(
        "stdio rpath wpath cpath unix sendfd proc exec tty",
        NULL) != 0)
        fatal("pledge failed");

    /* Free stuff that is not used in the client. */
    if (ptm_fd != -1)
        close(ptm_fd);
    /* 释放 client 端一些不需要的变量的内存空间 */
    options_free(global_options);
    options_free(global_s_options);
    options_free(global_w_options);
    environ_free(global_environ);

    /* Set up control mode. */
    /* 如果没有 -C 不会置位这个标记位 */
    if (client_flags & CLIENT_CONTROLCONTROL) {
        if (tcgetattr(STDIN_FILENO, &saved_tio) != 0) {
            fprintf(stderr, "tcgetattr failed: %s\n",
                strerror(errno));
            return (1);
        }
        cfmakeraw(&tio);
        tio.c_iflag = ICRNL|IXANY;
        tio.c_oflag = OPOST|ONLCR;
#ifdef NOKERNINFO
        tio.c_lflag = NOKERNINFO;
#endif
        tio.c_cflag = CREAD|CS8|HUPCL;
        tio.c_cc[VMIN] = 1;
        tio.c_cc[VTIME] = 0;
        cfsetispeed(&tio, cfgetispeed(&saved_tio));
        cfsetospeed(&tio, cfgetospeed(&saved_tio));
        tcsetattr(STDIN_FILENO, TCSANOW, &tio);
    }

    /* Send identify messages. */
    /* 发送身份信息，ttyname 是当前进程标准输入的设备名字，格式是 /dev/pts/[x]
     * cwd 是当前目录的路径名！！！
	 * 通过 libevent 框架将消息发送出去，接收端会通过对应
     * 的句柄执行 libevent 回调函数
     * */
    client_send_identify(ttynam, cwd);

    /* Send first command. */
    /* 一般地 msg == MSG_COMMAND
     * 并且发送的第一个命令缺省是 new-session
	 * */ 
    if (msg == MSG_COMMAND) {
        /* How big is the command? */
        size = 0;
        for (i = 0; i < argc; i++)
            size += strlen(argv[i]) + 1;
        if (size > MAX_IMSGSIZE - (sizeof *data)) {
            fprintf(stderr, "command too long\n");
            return (1);
        }
        data = xmalloc((sizeof *data) + size);

        /* Prepare command for server. */
        /* 打包构造通过 socket pair 传递给 client 的 socket */
        data->argc = argc;
        if (cmd_pack_argv(argc, argv, (char *)(data + 1), size) != 0) {
            fprintf(stderr, "command too long\n");
            free(data);
            return (1);
        }
        size += sizeof *data;

        /* Send the command. */
        /* 这里的 fd 为什么是 -1？
         * 通过 socket pair 发送给 child 进程，对应的是服务端
         * 纵使这里 argc == 0，服务端也会修正为 new-session
         * */
        if (proc_send(client_peer, msg, -1, data, size) != 0) {
            fprintf(stderr, "failed to send command\n");
            free(data);
            return (1);
        }
        free(data);
    } else if (msg == MSG_SHELL)
        proc_send(client_peer, msg, -1, NULL, 0);

    /* Start main loop. */
    /* 循环倾听 event 事件
     * 正常情况下 parent 进程也就是 client 会一直在这个循环
     * */
    proc_loop(client_proc, NULL);

    /* Run command if user requested exec, instead of exiting. */
    if (client_exittype == MSG_EXEC) {
        if (client_flags & CLIENT_CONTROLCONTROL)
            tcsetattr(STDOUT_FILENO, TCSAFLUSH, &saved_tio);
        client_exec(client_execshell, client_execcmd);
    }

    /* Print the exit message, if any, and exit. */
    if (client_attached) {
        if (client_exitreason != CLIENT_EXIT_NONE)
            printf("[%s]\n", client_exit_message());

        ppid = getppid();
        if (client_exittype == MSG_DETACHKILL && ppid > 1)
            kill(ppid, SIGHUP);
    } else if (client_flags & CLIENT_CONTROLCONTROL) {
        if (client_exitreason != CLIENT_EXIT_NONE)
            printf("%%exit %s\n", client_exit_message());
        else
            printf("%%exit\n");
        printf("\033\\");
        tcsetattr(STDOUT_FILENO, TCSAFLUSH, &saved_tio);
    } else if (client_exitreason != CLIENT_EXIT_NONE)
        fprintf(stderr, "%s\n", client_exit_message());
    /* 阻塞 client 的 stdio ，当无输入时，阻塞而不是返回 EAGAIN */
    setblocking(STDIN_FILENO, 1);
    return (client_exitval);
}

/* Send identify messages to server. */
/* 发送身份信息给服务器 */
static void
client_send_identify(const char *ttynam, const char *cwd)
{
    const char     *s;
    char        **ss;
    size_t          sslen;
    /* 一般情况，client_flags = CLIENT_UTF8 */
    int          fd, flags = client_flags;
    pid_t          pid;

    /* fd 为什么是 -1， -1 应该是表示无效的 fd 句柄
     * 通过 client_peer 将认证类消息发送出去给守护进程
     * */
    proc_send(client_peer, MSG_IDENTIFY_FLAGS, -1, &flags, sizeof flags);

    /* 获取 TERM 环境变量，发送给 server */
    if ((s = getenv("TERM")) == NULL)
        s = "";
    proc_send(client_peer, MSG_IDENTIFY_TERM, -1, s, strlen(s) + 1);

    /* 发送 tmux 进程的 stdin 描述符对应的终端设备名，格式 /dev/pts/[number] */
    proc_send(client_peer, MSG_IDENTIFY_TTYNAME, -1, ttynam,
        strlen(ttynam) + 1);
    /* 发送 tmux 执行时的工作路径 */
    proc_send(client_peer, MSG_IDENTIFY_CWD, -1, cwd, strlen(cwd) + 1);

    /* 复制一个标准输入句柄，赋值给 fd
     * 除了 flags 可以保持不一致，其他的可以认为是一致的，可互换的
     * */
    if ((fd = dup(STDIN_FILENO)) == -1)
        fatal("dup failed");
	/* 向 fd 写数据，就等价向该进程的标准输入写数据 */
    proc_send(client_peer, MSG_IDENTIFY_STDIN, fd, NULL, 0);

    pid = getpid();
    /* 发送 client 的 pid 给 server */
    proc_send(client_peer, MSG_IDENTIFY_CLIENTPID, -1, &pid, sizeof pid);

    for (ss = environ; *ss != NULL; ss++) {
        sslen = strlen(*ss) + 1;
        if (sslen > MAX_IMSGSIZE - IMSG_HEADER_SIZE)
            continue;
        /* 发送环境变量给 server ？？？ */
        proc_send(client_peer, MSG_IDENTIFY_ENVIRON, -1, *ss, sslen);
    }

    /* 标记身份信息已经发送完全  */
    proc_send(client_peer, MSG_IDENTIFY_DONE, -1, NULL, 0);
}

/* File write error callback. */
static void
client_write_error_callback(__unused struct bufferevent *bev,
    __unused short what, void *arg)
{
    struct client_file    *cf = arg;

    log_debug("write error file %d", cf->stream);

    bufferevent_free(cf->event);
    cf->event = NULL;

    close(cf->fd);
    cf->fd = -1;

    if (client_exitflag)
        client_exit();
}

/* File write callback. */
static void
client_write_callback(__unused struct bufferevent *bev, void *arg)
{
    struct client_file    *cf = arg;

    if (cf->closed && EVBUFFER_LENGTH(cf->event->output) == 0) {
        bufferevent_free(cf->event);
        close(cf->fd);
        RB_REMOVE(client_files, &client_files, cf);
        file_free(cf);
    }

    if (client_exitflag)
        client_exit();
}

/* Open write file. */
static void
client_write_open(void *data, size_t datalen)
{
    struct msg_write_open    *msg = data;
    const char        *path;
    struct msg_write_ready     reply;
    struct client_file     find, *cf;
    const int         flags = O_NONBLOCK|O_WRONLY|O_CREAT;
    int             error = 0;

    if (datalen < sizeof *msg)
        fatalx("bad MSG_WRITE_OPEN size");
    if (datalen == sizeof *msg)
        path = "-";
    else
        path = (const char *)(msg + 1);
    log_debug("open write file %d %s", msg->stream, path);

    find.stream = msg->stream;
    if ((cf = RB_FIND(client_files, &client_files, &find)) == NULL) {
        cf = file_create(NULL, msg->stream, NULL, NULL);
        RB_INSERT(client_files, &client_files, cf);
    } else {
        error = EBADF;
        goto reply;
    }
    if (cf->closed) {
        error = EBADF;
        goto reply;
    }

    cf->fd = -1;
    if (msg->fd == -1)
        cf->fd = open(path, msg->flags|flags, 0644);
    else {
        if (msg->fd != STDOUT_FILENO && msg->fd != STDERR_FILENO)
            errno = EBADF;
        else {
            cf->fd = dup(msg->fd);
            if (client_flags & CLIENT_CONTROL)
                close(msg->fd); /* can only be used once */
        }
    }
    if (cf->fd == -1) {
        error = errno;
        goto reply;
    }

    cf->event = bufferevent_new(cf->fd, NULL, client_write_callback,
        client_write_error_callback, cf);
    bufferevent_enable(cf->event, EV_WRITE);
    goto reply;

reply:
    reply.stream = msg->stream;
    reply.error = error;
    proc_send(client_peer, MSG_WRITE_READY, -1, &reply, sizeof reply);
}

/* Write to client file. */
static void
client_write_data(void *data, size_t datalen)
{
    struct msg_write_data    *msg = data;
    struct client_file     find, *cf;
    size_t             size = datalen - sizeof *msg;

    if (datalen < sizeof *msg)
        fatalx("bad MSG_WRITE size");
    find.stream = msg->stream;
    if ((cf = RB_FIND(client_files, &client_files, &find)) == NULL)
        fatalx("unknown stream number");
    log_debug("write %zu to file %d", size, cf->stream);

    if (cf->event != NULL)
        bufferevent_write(cf->event, msg + 1, size);
}

/* Close client file. */
static void
client_write_close(void *data, size_t datalen)
{
    struct msg_write_close    *msg = data;
    struct client_file     find, *cf;

    if (datalen != sizeof *msg)
        fatalx("bad MSG_WRITE_CLOSE size");
    find.stream = msg->stream;
    if ((cf = RB_FIND(client_files, &client_files, &find)) == NULL)
        fatalx("unknown stream number");
    log_debug("close file %d", cf->stream);

    if (cf->event == NULL || EVBUFFER_LENGTH(cf->event->output) == 0) {
        if (cf->event != NULL)
            bufferevent_free(cf->event);
        if (cf->fd != -1)
            close(cf->fd);
        RB_REMOVE(client_files, &client_files, cf);
        file_free(cf);
    }
}

/* File read callback. */
static void
client_read_callback(__unused struct bufferevent *bev, void *arg)
{
    struct client_file    *cf = arg;
    void            *bdata;
    size_t             bsize;
    struct msg_read_data    *msg;
    size_t             msglen;

    msg = xmalloc(sizeof *msg);
    for (;;) {
        bdata = EVBUFFER_DATA(cf->event->input);
        bsize = EVBUFFER_LENGTH(cf->event->input);

        if (bsize == 0)
            break;
        if (bsize > MAX_IMSGSIZE - IMSG_HEADER_SIZE - sizeof *msg)
            bsize = MAX_IMSGSIZE - IMSG_HEADER_SIZE - sizeof *msg;
        log_debug("read %zu from file %d", bsize, cf->stream);

        msglen = (sizeof *msg) + bsize;
        msg = xrealloc(msg, msglen);
        msg->stream = cf->stream;
        memcpy(msg + 1, bdata, bsize);
        proc_send(client_peer, MSG_READ, -1, msg, msglen);

        evbuffer_drain(cf->event->input, bsize);
    }
    free(msg);
}

/* File read error callback. */
static void
client_read_error_callback(__unused struct bufferevent *bev,
    __unused short what, void *arg)
{
    struct client_file    *cf = arg;
    struct msg_read_done     msg;

    log_debug("read error file %d", cf->stream);

    msg.stream = cf->stream;
    msg.error = 0;
    proc_send(client_peer, MSG_READ_DONE, -1, &msg, sizeof msg);

    bufferevent_free(cf->event);
    close(cf->fd);
    RB_REMOVE(client_files, &client_files, cf);
    file_free(cf);
}

/* Open read file. */
static void
client_read_open(void *data, size_t datalen)
{
    struct msg_read_open    *msg = data;
    const char        *path;
    struct msg_read_done     reply;
    struct client_file     find, *cf;
    const int         flags = O_NONBLOCK|O_RDONLY;
    int             error = 0;

    if (datalen < sizeof *msg)
        fatalx("bad MSG_READ_OPEN size");
    if (datalen == sizeof *msg)
        path = "-";
    else
        path = (const char *)(msg + 1);
    log_debug("open read file %d %s", msg->stream, path);

    find.stream = msg->stream;
    if ((cf = RB_FIND(client_files, &client_files, &find)) == NULL) {
        cf = file_create(NULL, msg->stream, NULL, NULL);
        RB_INSERT(client_files, &client_files, cf);
    } else {
        error = EBADF;
        goto reply;
    }
    if (cf->closed) {
        error = EBADF;
        goto reply;
    }

    cf->fd = -1;
    if (msg->fd == -1)
        cf->fd = open(path, flags);
    else {
        if (msg->fd != STDIN_FILENO)
            errno = EBADF;
        else {
            cf->fd = dup(msg->fd);
            close(msg->fd); /* can only be used once */
        }
    }
    if (cf->fd == -1) {
        error = errno;
        goto reply;
    }

    cf->event = bufferevent_new(cf->fd, client_read_callback, NULL,
        client_read_error_callback, cf);
    bufferevent_enable(cf->event, EV_READ);
    return;

reply:
    reply.stream = msg->stream;
    reply.error = error;
    proc_send(client_peer, MSG_READ_DONE, -1, &reply, sizeof reply);
}

/* Run command in shell; used for -c. */
static __dead void
client_exec(const char *shell, const char *shellcmd)
{
    const char    *name, *ptr;
    char        *argv0;

    log_debug("shell %s, command %s", shell, shellcmd);

    ptr = strrchr(shell, '/');
    if (ptr != NULL && *(ptr + 1) != '\0')
        name = ptr + 1;
    else
        name = shell;
    if (client_flags & CLIENT_LOGIN)
        xasprintf(&argv0, "-%s", name);
    else
        xasprintf(&argv0, "%s", name);
    setenv("SHELL", shell, 1);

    proc_clear_signals(client_proc, 1);

    setblocking(STDIN_FILENO, 1);
    setblocking(STDOUT_FILENO, 1);
    setblocking(STDERR_FILENO, 1);
    closefrom(STDERR_FILENO + 1);

    execl(shell, argv0, "-c", shellcmd, (char *) NULL);
    fatal("execl failed");
}

/* Callback to handle signals in the client. */
/* 作为 client 端倾听 libevent 框架下 event 信号事件的回调函数 */
static void
client_signal(int sig)
{
    struct sigaction sigact;
    int         status;

    if (sig == SIGCHLD)
        waitpid(WAIT_ANY, &status, WNOHANG);
    else if (!client_attached) {
        if (sig == SIGTERM)
            proc_exit(client_proc);
    } else {
        switch (sig) {
        case SIGHUP:
            client_exitreason = CLIENT_EXIT_LOST_TTY;
            client_exitval = 1;
            proc_send(client_peer, MSG_EXITING, -1, NULL, 0);
            break;
        case SIGTERM:
            client_exitreason = CLIENT_EXIT_TERMINATED;
            client_exitval = 1;
            proc_send(client_peer, MSG_EXITING, -1, NULL, 0);
            break;
        case SIGWINCH:
            proc_send(client_peer, MSG_RESIZE, -1, NULL, 0);
            break;
        case SIGCONT:
            memset(&sigact, 0, sizeof sigact);
            sigemptyset(&sigact.sa_mask);
            sigact.sa_flags = SA_RESTART;
            sigact.sa_handler = SIG_IGN;
            if (sigaction(SIGTSTP, &sigact, NULL) != 0)
                fatal("sigaction failed");
            proc_send(client_peer, MSG_WAKEUP, -1, NULL, 0);
            break;
        }
    }
}

/* Callback for client read events. */
/* client 端接受 server 发送的消息事件的回调函数 */
static void
client_dispatch(struct imsg *imsg, __unused void *arg)
{
    if (imsg == NULL) {
        client_exitreason = CLIENT_EXIT_LOST_SERVER;
        client_exitval = 1;
        proc_exit(client_proc);
        return;
    }

    if (client_attached)
        client_dispatch_attached(imsg);
    else
        client_dispatch_wait(imsg);
}

/* Dispatch imsgs when in wait state (before MSG_READY). */
static void
client_dispatch_wait(struct imsg *imsg)
{
    char        *data;
    ssize_t         datalen;
    int         retval;
    static int     pledge_applied;

    /*
     * "sendfd" is no longer required once all of the identify messages
     * have been sent. We know the server won't send us anything until that
     * point (because we don't ask it to), so we can drop "sendfd" once we
     * get the first message from the server.
     */
    if (!pledge_applied) {
        if (pledge(
            "stdio rpath wpath cpath unix proc exec tty",
            NULL) != 0)
            fatal("pledge failed");
        pledge_applied = 1;
    }

    data = imsg->data;
    datalen = imsg->hdr.len - IMSG_HEADER_SIZE;

    switch (imsg->hdr.type) {
    case MSG_EXIT:
    case MSG_SHUTDOWN:
        if (datalen != sizeof retval && datalen != 0)
            fatalx("bad MSG_EXIT size");
        if (datalen == sizeof retval) {
            memcpy(&retval, data, sizeof retval);
            client_exitval = retval;
        }
        client_exitflag = 1;
        client_exit();
        break;
    case MSG_READY:
        if (datalen != 0)
            fatalx("bad MSG_READY size");

        client_attached = 1;
        proc_send(client_peer, MSG_RESIZE, -1, NULL, 0);
        break;
    case MSG_VERSION:
        if (datalen != 0)
            fatalx("bad MSG_VERSION size");

        fprintf(stderr, "protocol version mismatch "
            "(client %d, server %u)\n", PROTOCOL_VERSION,
            imsg->hdr.peerid & 0xff);
        client_exitval = 1;
        proc_exit(client_proc);
        break;
    case MSG_SHELL:
        if (datalen == 0 || data[datalen - 1] != '\0')
            fatalx("bad MSG_SHELL string");

        client_exec(data, shell_command);
        /* NOTREACHED */
    case MSG_DETACH:
    case MSG_DETACHKILL:
        proc_send(client_peer, MSG_EXITING, -1, NULL, 0);
        break;
    case MSG_EXITED:
        proc_exit(client_proc);
        break;
    case MSG_READ_OPEN:
        client_read_open(data, datalen);
        break;
    case MSG_WRITE_OPEN:
        client_write_open(data, datalen);
        break;
    case MSG_WRITE:
        client_write_data(data, datalen);
        break;
    case MSG_WRITE_CLOSE:
        client_write_close(data, datalen);
        break;
    case MSG_OLDSTDERR:
    case MSG_OLDSTDIN:
    case MSG_OLDSTDOUT:
        fprintf(stderr, "server version is too old for client\n");
        proc_exit(client_proc);
        break;
    }
}

/* Dispatch imsgs in attached state (after MSG_READY). */
static void
client_dispatch_attached(struct imsg *imsg)
{
    struct sigaction     sigact;
    char            *data;
    ssize_t             datalen;

    data = imsg->data;
    datalen = imsg->hdr.len - IMSG_HEADER_SIZE;

    switch (imsg->hdr.type) {
    case MSG_DETACH:
    case MSG_DETACHKILL:
        if (datalen == 0 || data[datalen - 1] != '\0')
            fatalx("bad MSG_DETACH string");

        client_exitsession = xstrdup(data);
        client_exittype = imsg->hdr.type;
        if (imsg->hdr.type == MSG_DETACHKILL)
            client_exitreason = CLIENT_EXIT_DETACHED_HUP;
        else
            client_exitreason = CLIENT_EXIT_DETACHED;
        proc_send(client_peer, MSG_EXITING, -1, NULL, 0);
        break;
    case MSG_EXEC:
        if (datalen == 0 || data[datalen - 1] != '\0' ||
            strlen(data) + 1 == (size_t)datalen)
            fatalx("bad MSG_EXEC string");
        client_execcmd = xstrdup(data);
        client_execshell = xstrdup(data + strlen(data) + 1);

        client_exittype = imsg->hdr.type;
        proc_send(client_peer, MSG_EXITING, -1, NULL, 0);
        break;
    case MSG_EXIT:
        if (datalen != 0 && datalen != sizeof (int))
            fatalx("bad MSG_EXIT size");

        proc_send(client_peer, MSG_EXITING, -1, NULL, 0);
        client_exitreason = CLIENT_EXIT_EXITED;
        break;
    case MSG_EXITED:
        if (datalen != 0)
            fatalx("bad MSG_EXITED size");

        proc_exit(client_proc);
        break;
    case MSG_SHUTDOWN:
        if (datalen != 0)
            fatalx("bad MSG_SHUTDOWN size");

        proc_send(client_peer, MSG_EXITING, -1, NULL, 0);
        client_exitreason = CLIENT_EXIT_SERVER_EXITED;
        client_exitval = 1;
        break;
    case MSG_SUSPEND:
        if (datalen != 0)
            fatalx("bad MSG_SUSPEND size");

        memset(&sigact, 0, sizeof sigact);
        sigemptyset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;
        sigact.sa_handler = SIG_DFL;
        if (sigaction(SIGTSTP, &sigact, NULL) != 0)
            fatal("sigaction failed");
        kill(getpid(), SIGTSTP);
        break;
    case MSG_LOCK:
        if (datalen == 0 || data[datalen - 1] != '\0')
            fatalx("bad MSG_LOCK string");

        system(data);
        proc_send(client_peer, MSG_UNLOCK, -1, NULL, 0);
        break;
    }
}
