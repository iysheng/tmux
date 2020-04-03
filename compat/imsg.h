/*	$OpenBSD: imsg.h,v 1.4 2017/03/24 09:34:12 nicm Exp $	*/

/*
 * Copyright (c) 2006, 2007 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2006, 2007, 2008 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _IMSG_H_
#define _IMSG_H_

#define IBUF_READ_SIZE		65535
#define IMSG_HEADER_SIZE	sizeof(struct imsg_hdr)
#define MAX_IMSGSIZE		16384

struct ibuf {
	TAILQ_ENTRY(ibuf)	 entry;
	u_char			*buf;
	size_t			 size;
	size_t			 max;
	/* 描述下一次写数据的位置 */
	size_t			 wpos;
	size_t			 rpos;
	/* 这个 fd 是做什么的？？？ */
	int			 fd;
};

/* 展开 TAILQ_HEAD */
#if 0
struct msgbuf {
	/* 管理的是 struct ibuf 实例 */
	struct {
		struct ibuf *tqh_first;	/* first element */
		struct ibuf **tqh_last;	/* addr of last next element */
	} bufs;
	/* 标记 queue 了多少需要发送出去的消息 */
	uint32_t		 queued;
	/* 读写消息句柄 */
	int			 fd;
};
#endif

struct msgbuf {
	/* 管理的是 struct ibuf 实例 */
	TAILQ_HEAD(, ibuf)	 bufs;
	uint32_t		 queued;
	/* 读写消息句柄 */
	int			 fd;
};

struct ibuf_read {
	u_char			 buf[IBUF_READ_SIZE];
	u_char			*rptr;
	size_t			 wpos;
};

struct imsg_fd {
	TAILQ_ENTRY(imsg_fd)	entry;
	int			fd;
};

struct imsgbuf {
	TAILQ_HEAD(, imsg_fd)	 fds;
	/* 这个是管理读消息的实例 */
	struct ibuf_read	 r;
	/* 这个是管理写消息的管理实例
	 * 发送的消息都会添加到这个 struct msgbuf 管理的 struct ibuf 实例
	 * 在通过系统调用 sendmsg 发送消息到 socket 时，会将该消息填充到
	 * struct msgbuf 实例
	 * */
	struct msgbuf		 w;
	/* 读写该消息的句柄 */
	int			 fd;
	/* 该结构体所属的进程 pid */
	pid_t			 pid;
};

#define IMSGF_HASFD	1

/* 消息头部， client 和 server 通讯的消息包头部 */
struct imsg_hdr {
	/* 消息类型 */
	uint32_t	 type;
	uint16_t	 len;
	uint16_t	 flags;
	uint32_t	 peerid;
	uint32_t	 pid;
};

/* 含有头部的消息抽象 */
struct imsg {
	struct imsg_hdr	 hdr;
	int		 fd;
	void		*data;
};


/* buffer.c */
struct ibuf	*ibuf_open(size_t);
struct ibuf	*ibuf_dynamic(size_t, size_t);
int		 ibuf_add(struct ibuf *, const void *, size_t);
void		*ibuf_reserve(struct ibuf *, size_t);
void		*ibuf_seek(struct ibuf *, size_t, size_t);
size_t		 ibuf_size(struct ibuf *);
size_t		 ibuf_left(struct ibuf *);
void		 ibuf_close(struct msgbuf *, struct ibuf *);
int		 ibuf_write(struct msgbuf *);
void		 ibuf_free(struct ibuf *);
void		 msgbuf_init(struct msgbuf *);
void		 msgbuf_clear(struct msgbuf *);
int		 msgbuf_write(struct msgbuf *);
void		 msgbuf_drain(struct msgbuf *, size_t);

/* imsg.c */
void	 imsg_init(struct imsgbuf *, int);
ssize_t	 imsg_read(struct imsgbuf *);
ssize_t	 imsg_get(struct imsgbuf *, struct imsg *);
int	 imsg_compose(struct imsgbuf *, uint32_t, uint32_t, pid_t, int,
	    const void *, uint16_t);
int	 imsg_composev(struct imsgbuf *, uint32_t, uint32_t,  pid_t, int,
	    const struct iovec *, int);
struct ibuf *imsg_create(struct imsgbuf *, uint32_t, uint32_t, pid_t, uint16_t);
int	 imsg_add(struct ibuf *, const void *, uint16_t);
void	 imsg_close(struct imsgbuf *, struct ibuf *);
void	 imsg_free(struct imsg *);
int	 imsg_flush(struct imsgbuf *);
void	 imsg_clear(struct imsgbuf *);

#endif
