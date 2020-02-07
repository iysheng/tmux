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
#include <sys/stat.h>
#include <sys/utsname.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <langinfo.h>
#include <locale.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "tmux.h"

/* 包含了管理保存 server 类型选项的 rb head */
struct options	*global_options;	/* server options */
/* 包含了管理保存 session 类型的选项的 rb head */
struct options	*global_s_options;	/* session options */
/* 包含了管理保存 window 类型选项的 rb head */
struct options	*global_w_options;	/* window options */
struct environ	*global_environ;

struct timeval	 start_time;
const char	*socket_path;
int		 ptm_fd = -1;
const char	*shell_command;

static __dead void	 usage(void);
static char		*make_label(const char *, char **);

static const char	*getshell(void);
static int		 checkshell(const char *);

static __dead void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-2CluvV] [-c shell-command] [-f file] [-L socket-name]\n"
	    "            [-S socket-path] [command [flags]]\n",
	    getprogname());
	exit(1);
}

static const char *
getshell(void)
{
	struct passwd	*pw;
	const char	*shell;

	shell = getenv("SHELL");
	if (checkshell(shell))
		return (shell);

	pw = getpwuid(getuid());
	if (pw != NULL && checkshell(pw->pw_shell))
		return (pw->pw_shell);

	return (_PATH_BSHELL);
}

static int
checkshell(const char *shell)
{
	if (shell == NULL || *shell != '/')
		return (0);
	if (areshell(shell))
		return (0);
	if (access(shell, X_OK) != 0)
		return (0);
	return (1);
}

int
areshell(const char *shell)
{
	const char	*progname, *ptr;

	if ((ptr = strrchr(shell, '/')) != NULL)
		ptr++;
	else
		ptr = shell;
	progname = getprogname();
	if (*progname == '-')
		progname++;
	if (strcmp(ptr, progname) == 0)
		return (1);
	return (0);
}

static char *
make_label(const char *label, char **cause)
{
	char		*base, resolved[PATH_MAX], *path, *s;
	struct stat	 sb;
	uid_t		 uid;

	*cause = NULL;

	if (label == NULL)
		/* 修正 socket 的名字包含 "default" */
		label = "default";
	/* 获取当前用户的 uid */
	uid = getuid();

	if ((s = getenv("TMUX_TMPDIR")) != NULL && *s != '\0')
		xasprintf(&base, "%s/tmux-%ld", s, (long)uid);
	else
		/* 一般不会设置 TMUX_TMPDIR 环境变量，所以都会走到这里
		 * 默认创建本地 socket 的路径是 /tmp/tmux-1000 # yys uid = 1000
		 * 将这个路径字符串保存到 base 指向的内存空间
		 * */
		xasprintf(&base, "%s/tmux-%ld", _PATH_TMP, (long)uid);
	/* 将符号链接展开为实际的绝对路径名，保存到 resolved 指向的内存空间 */
	if (realpath(base, resolved) == NULL &&
	    strlcpy(resolved, base, sizeof resolved) >= sizeof resolved) {
		errno = ERANGE;
		free(base);
		goto fail;
	}
	free(base);

	/* 创建目录对应的目录，默认就是 /tmp/tmux-1000 # yys uid = 1000 目录，
	 * 所有者拥有读写执行权限 */
	if (mkdir(resolved, S_IRWXU) != 0 && errno != EEXIST)
		goto fail;
	if (lstat(resolved, &sb) != 0)
		goto fail;
	if (!S_ISDIR(sb.st_mode)) {
		errno = ENOTDIR;
		goto fail;
	}
	if (sb.st_uid != uid || (sb.st_mode & S_IRWXO) != 0) {
		errno = EACCES;
		goto fail;
	}
	/* 设置本地 socket 的文件名字 /tmp/tmux-1000/default
	 * 将名字的首地址保存到 path 变量，返回 */
	xasprintf(&path, "%s/%s", resolved, label);
	return (path);

fail:
	xasprintf(cause, "error creating %s (%s)", resolved, strerror(errno));
	return (NULL);
}

void
setblocking(int fd, int state)
{
	int mode;

	if ((mode = fcntl(fd, F_GETFL)) != -1) {
		if (!state)
			mode |= O_NONBLOCK;
		else
			mode &= ~O_NONBLOCK;
		fcntl(fd, F_SETFL, mode);
	}
}

const char *
find_cwd(void)
{
	char		 resolved1[PATH_MAX], resolved2[PATH_MAX];
	static char	 cwd[PATH_MAX];
	const char	*pwd;

	/* 优先获取当前工作路径的名字 */
	if (getcwd(cwd, sizeof cwd) == NULL)
		return (NULL);
	if ((pwd = getenv("PWD")) == NULL || *pwd == '\0')
		return (cwd);

	/*
	 * We want to use PWD so that symbolic links are maintained,
	 * but only if it matches the actual working directory.
	 */
	if (realpath(pwd, resolved1) == NULL)
		return (cwd);
	if (realpath(cwd, resolved2) == NULL)
		return (cwd);
	if (strcmp(resolved1, resolved2) != 0)
		return (cwd);
	return (pwd);
}

const char *
find_home(void)
{
	struct passwd		*pw;
	static const char	*home;

	if (home != NULL)
		return (home);

	home = getenv("HOME");
	if (home == NULL || *home == '\0') {
		pw = getpwuid(getuid());
		if (pw != NULL)
			home = pw->pw_dir;
		else
			home = NULL;
	}

	return (home);
}

const char *
getversion(void)
{
	return TMUX_VERSION;
}

int
main(int argc, char **argv)
{
	char					*path, *label, *cause, **var;
	const char				*s, *shell, *cwd;
	int					 opt, flags, keys;
	const struct options_table_entry	*oe;

	if (setlocale(LC_CTYPE, "en_US.UTF-8") == NULL &&
	    setlocale(LC_CTYPE, "C.UTF-8") == NULL) {
		if (setlocale(LC_CTYPE, "") == NULL)
			errx(1, "invalid LC_ALL, LC_CTYPE or LANG");
		s = nl_langinfo(CODESET);
		if (strcasecmp(s, "UTF-8") != 0 && strcasecmp(s, "UTF8") != 0)
			errx(1, "need UTF-8 locale (LC_CTYPE) but have %s", s);
	}

	setlocale(LC_TIME, "");
	tzset();

	if (**argv == '-')
		flags = CLIENT_LOGIN;
	else
		flags = 0;

	label = path = NULL;
	while ((opt = getopt(argc, argv, "2c:Cdf:lL:qS:uUvV")) != -1) {
		switch (opt) {
		case '2':
			flags |= CLIENT_256COLOURS;
			break;
		case 'c':
			shell_command = optarg;
			break;
		case 'C':
			if (flags & CLIENT_CONTROL)
				flags |= CLIENT_CONTROLCONTROL;
			else
				flags |= CLIENT_CONTROL;
			break;
		case 'f':
			set_cfg_file(optarg);
			break;
			/* 打印 tmux 的版本号 */
 		case 'V':
			printf("%s %s\n", getprogname(), getversion());
 			exit(0);
		case 'l':
			flags |= CLIENT_LOGIN;
			break;
			/* 指定创建的 socket 的名字，默认是 default */
		case 'L':
			free(label);
			label = xstrdup(optarg);
			break;
		case 'q':
			break;
			/* 指定创建的 socket 的路径，默认是 /tmp
			 * 指定了 -S 选项后，会忽略掉 -L 选项参数
			 * */
		case 'S':
			free(path);
			path = xstrdup(optarg);
			break;
		case 'u':
			flags |= CLIENT_UTF8;
			break;
		case 'v':
			/* 使能日志记录 */
			log_add_level();
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (shell_command != NULL && argc != 0)
		usage();

	if ((ptm_fd = getptmfd()) == -1)
		err(1, "getptmfd");
	if (pledge("stdio rpath wpath cpath flock fattr unix getpw sendfd "
	    "recvfd proc exec tty ps", NULL) != 0)
		err(1, "pledge");

	/*
	 * tmux is a UTF-8 terminal, so if TMUX is set, assume UTF-8.
	 * Otherwise, if the user has set LC_ALL, LC_CTYPE or LANG to contain
	 * UTF-8, it is a safe assumption that either they are using a UTF-8
	 * terminal, or if not they know that output from UTF-8-capable
	 * programs may be wrong.
	 */
	if (getenv("TMUX") != NULL)
		flags |= CLIENT_UTF8;
	else {
		s = getenv("LC_ALL");
		if (s == NULL || *s == '\0')
			s = getenv("LC_CTYPE");
		if (s == NULL || *s == '\0')
			s = getenv("LANG");
		if (s == NULL || *s == '\0')
			s = "";
		/* 如果环境变量 LC_ALL 的值，包含 UTF-8 或者 UTF8 这类字段
		 * 那么会设置 flags 标志位 CLIENT_UTF8
		 * */
		if (strcasestr(s, "UTF-8") != NULL ||
		    strcasestr(s, "UTF8") != NULL)
			flags |= CLIENT_UTF8;
	}

	/* 将系统环境变量拆分为 key 和 value 的格式保存到
	 * global_environ 这个 rb tree 的根节点
	 * 这里的 environ 是保存系统环境变量的全局变量指针
	 * */
	global_environ = environ_create();
	for (var = environ; *var != NULL; var++)
		environ_put(global_environ, *var);
	if ((cwd = find_cwd()) != NULL)
		environ_set(global_environ, "PWD", "%s", cwd);

	/* 初始化这 3 个 rbtree 根节点 */
	global_options = options_create(NULL);
	global_s_options = options_create(NULL);
	global_w_options = options_create(NULL);
	/* 遍历全局数组 options_table，根据不同的类型，添加到不同的 rbtree 节点管理 */
	for (oe = options_table; oe->name != NULL; oe++) {
		/* 如果是 server 类型的，赋值给管理 server 的 global_options */
		if (oe->scope & OPTIONS_TABLE_SERVER)
			options_default(global_options, oe);
		/* 如果是 session 类型的，赋值给管理 server 的 global_s_options */
		if (oe->scope & OPTIONS_TABLE_SESSION)
			options_default(global_s_options, oe);
		/* 如果是 window 类型的，赋值给管理 server 的 global_w_options */
		if (oe->scope & OPTIONS_TABLE_WINDOW)
			options_default(global_w_options, oe);
	}

	/*
	 * The default shell comes from SHELL or from the user's passwd entry
	 * if available.
	 */
	shell = getshell();
	/* 设置 session 类型的选项 default-shell */
	options_set_string(global_s_options, "default-shell", 0, "%s", shell);

	/* Override keys to vi if VISUAL or EDITOR are set. */
	if ((s = getenv("VISUAL")) != NULL || (s = getenv("EDITOR")) != NULL) {
		if (strrchr(s, '/') != NULL)
			s = strrchr(s, '/') + 1;
		if (strstr(s, "vi") != NULL)
			keys = MODEKEY_VI;
		else
			keys = MODEKEY_EMACS;
		options_set_number(global_s_options, "status-keys", keys);
		/* 这个对应的是 mod key？？？ Ctrl - b （default）
		 * 好像不是
		 * */
		options_set_number(global_w_options, "mode-keys", keys);
	}

	/*
	 * If socket is specified on the command-line with -S or -L, it is
	 * used. Otherwise, $TMUX is checked and if that fails "default" is
	 * used.
	 */
	if (path == NULL && label == NULL) {
		s = getenv("TMUX");
		if (s != NULL && *s != '\0' && *s != ',') {
			path = xstrdup(s);
			path[strcspn(path, ",")] = '\0';
		}
	}
	/* 根据 label 如果没有通过 -L 选项指定，默认是 NULL，
	 * 初始化保存本地 socket 的路径名到 path 并返回， cause 保存的
	 * 是错误信息
	 * */
	if (path == NULL && (path = make_label(label, &cause)) == NULL) {
		if (cause != NULL) {
			fprintf(stderr, "%s\n", cause);
			free(cause);
		}
		exit(1);
	}
	/* 记录保存 socket path 的路径到全局变量 socket_path，这是第一阶段做的比较重要的事情 */
	socket_path = path;
	/* 释放 label 的内存空间，如果没有 -L 选项初始化，空释放 */
	free(label);

	/* Pass control to the client. */
	/* 将控制权交给 client
	 * 一般情况，即 tmux 未加任何参数，argc = 0, argv = NULL 那么 flags |= CLIENT_UTF8
	 * */
	exit(client_main(osdep_event_init(), argc, argv, flags));
}
