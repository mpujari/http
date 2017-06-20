/*
 * Copyright (c) 2015 Sunil Nimmagadda <sunil@openbsd.org>
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <err.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http.h"

#define P_PRE	100
#define P_OK	200
#define P_INTER	300
#define N_TRANS	400
#define	N_PERM	500

static int	ftp_auth(const char *, const char *);
static int	ftp_pasv(int);
static int	ftp_size(int, const char *, off_t *);
static ssize_t	ftp_readline(int, char *, size_t);
static int	ftp_command(int, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)))
		    __attribute__((__nonnull__ (2)));

static int	ctrl_sock;
static int	data_sock;

void
ftp_connect(struct url *url, int timeout)
{
	char	buf[MAX_LINE];
	int	r = -1;

	ctrl_sock = tcp_connect(url->host, url->port, timeout);
	if (proxy)
		proxy_connect(url, ctrl_sock);

	/* greeting */
	if ((r = ftp_readline(ctrl_sock, buf, sizeof buf)) != P_OK)
		goto error;

	log_info("Connected to %s\n", url->host);
	if ((r = ftp_auth(NULL, NULL)) != P_OK)
		goto error;

	return;
error:
	if (r == -1)
		warnx("Can't connect or login to host `%s'", url->host);

	ftp_command(ctrl_sock, "QUIT");
	close(ctrl_sock);
}

struct url *
ftp_get(struct url *url)
{
	char	*dir;

	log_info("Using binary mode to transfer files.\n");
	if (ftp_command(ctrl_sock, "TYPE I") != P_OK)
		errx(1, "Failed to set mode to binary");

	dir = dirname(url->path);
	if (ftp_command(ctrl_sock, "CWD %s", dir) != P_OK)
		errx(1, "CWD command failed");

	if (url->offset &&
	    ftp_command(ctrl_sock, "REST %lld", url->offset) != P_OK)
		errx(1, "REST command failed");

	if (ftp_size(ctrl_sock, url->fname, &url->file_sz) != P_OK)
		errx(1, "failed to get size of file %s", url->fname);

	if ((data_sock = ftp_pasv(ctrl_sock)) == -1)
		errx(1, "error retrieving file %s", url->fname);

	if (ftp_command(ctrl_sock, "RETR %s", url->fname) != P_PRE)
		errx(1, "error retrieving file %s", url->fname);

	return url;
}

void
ftp_save(struct url *url, int fd)
{
	FILE	*fp;
	ssize_t	 r;

	if ((fp = fdopen(fd, "w")) == NULL)
		err(1, "%s: fdopen", __func__);

	while ((r = read(data_sock, tmp_buf, TMPBUF_LEN)) != 0) {
		if (r == -1)
			err(1, "%s: read", __func__);

		url->offset += r;
		if (fwrite(tmp_buf, r, 1, fp) != 1)
			err(1, "%s: fwrite", __func__);
	}

	fclose(fp);
	close(data_sock);
}

void
ftp_quit(struct url *url)
{
	char	 buf[MAX_LINE];

	if (ftp_readline(ctrl_sock, buf, sizeof buf) != P_OK)
		errx(1, "error retrieving file %s", url->fname);

	ftp_command(ctrl_sock, "QUIT");
	close(ctrl_sock);

}

static ssize_t
ftp_readline(int fd, char *buf, size_t len)
{
	ssize_t		 r;
	char		 code[4];
	const char	*errstr;
	int		 lookup[] = { P_PRE, P_OK, P_INTER, N_TRANS, N_PERM };

	switch (r = readline(fd, buf, len)) {
		case -1:
			return -1;
		case 0:
			errx(1, "%s: socket closed", __func__);
		default:
			log_info("%s\n", buf);
			if (r < 4)
				errx(1, "%s: Response too short", __func__);
	}
	(void)strlcpy(code, buf, sizeof code);
	if (buf[3] == ' ')
		goto done;

	/* multi-line reply */
	while (!(strncmp(code, buf, 3) == 0 && buf[3] == ' ')) {
		switch (r = readline (fd, buf, len)) {
		case -1:
			return -1;
		case 0:
			errx(1, "%s: socket closed", __func__);
		default:
			log_info("%s\n", buf);
			if (r < 4)
				continue;
		}
	}

 done:
	(void)strtonum(code, 100, 553, &errstr);
	if (errstr)
		errx(1, "%s: Response code is %s: %s", __func__, errstr, code);

	return lookup[code[0] - '1'];
}

static int
ftp_command(int fd, const char *fmt, ...)
{
	va_list	ap;
	char	buf[MAX_LINE];
	ssize_t	r;

	va_start(ap, fmt);
	r = vwriteline(fd, fmt, ap);
	va_end(ap);
	switch (r) {
	case -1:
		return -1;
	case 0:
		errx(1, "ftp_command: socket closed");
	}

	return ftp_readline(fd, buf, sizeof buf);
}

#define pack2(var, off) \
	(((var[(off) + 0] & 0xff) << 8) | ((var[(off) + 1] & 0xff) << 0))
#define pack4(var, off) \
	(((var[(off) + 0] & 0xff) << 24) | ((var[(off) + 1] & 0xff) << 16) | \
	 ((var[(off) + 2] & 0xff) << 8) | ((var[(off) + 3] & 0xff) << 0))

/* Establish data connection and return the socket descriptor */
static int
ftp_pasv(int fd)
{
	struct sockaddr_in	sa;
	char			buf[MAX_LINE], *s, *e;
	uint			addr[4], port[2];
	int			ret, sock;

	if (writeline(fd, "PASV") == -1)
		return -1;

	if (ftp_readline(fd, buf, sizeof buf) != P_OK)
		return -1;

	if ((s = strchr(buf, '(')) == NULL || (e = strchr(s, ')')) == NULL) {
		warnx("Malformed PASV reply");
		return -1;
	}

	s++;
	*e = '\0';
	ret = sscanf(s, "%u,%u,%u,%u,%u,%u",
	    &addr[0], &addr[1], &addr[2], &addr[3],
	    &port[0], &port[1]);

	if (ret != 6) {
		warnx("Passive mode address scan failure");
		return -1;
	}

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_len = sizeof(sa);
	sa.sin_addr.s_addr = htonl(pack4(addr, 0));
	sa.sin_port = htons(pack2(port, 0));

	if ((sock = socket(sa.sin_family, SOCK_STREAM, 0)) == -1)
		err(1, "ftp_pasv: socket");

	if (connect(sock, (struct sockaddr *)&sa, sa.sin_len) == -1)
		err(1, "ftp_pasv: connect");

	return sock;
}

static int
ftp_size(int fd, const char *fn, off_t *sizep)
{
	char		 buf[MAX_LINE], *s;
	const char	*errstr;
	off_t		 file_sz;
	int		 code;

	if (writeline(fd, "SIZE %s", fn) == -1)
		return -1;

	if ((code = ftp_readline(fd, buf, sizeof buf)) != P_OK)
		return code;

	if ((s = strchr(buf, ' ')) == NULL) {
		warnx("Malformed SIZE reply");
		return -1;
	}

	s++;
	file_sz = strtonum(s, 0, LLONG_MAX, &errstr);
	if (errstr)
		errx(1, "ftp_size: size is %s: %s", errstr, s);

	if (sizep)
		*sizep = file_sz;

	return code;
}

static int
ftp_auth(const char *user, const char *pass)
{
	int	code, ret;
	char	hn[MAXHOSTNAMELEN+1], *un;
	char	addr[LOGIN_NAME_MAX+MAXHOSTNAMELEN+3];

	code = ftp_command(ctrl_sock, "USER %s", user ? user : "anonymous");
	if (code != P_OK && code != P_INTER)
		return code;

	if (pass == NULL) {
		if (gethostname(hn, sizeof hn) == -1)
			err(1, "ftp_auth: gethostname");

		un = getlogin();
		ret = snprintf(addr, sizeof addr, "%s@%s",
		    un ? un : "anonymous", hn);
		if (ret == -1 || ret > sizeof addr)
			errx(1, "addr too long");
	}

	code = ftp_command(ctrl_sock, "PASS %s", pass ? pass : addr);
	return code;
}
