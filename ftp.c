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

static int	 ftp_auth(const char *, const char *);
static FILE	*ftp_pasv(void);
static int	 ftp_size(const char *, off_t *);
static int	 ftp_getline(char **, size_t *);
static int	 ftp_command(const char *, ...)
		    __attribute__((__format__ (printf, 1, 2)))
		    __attribute__((__nonnull__ (1)));

static FILE	*ctrl_fp;
static FILE	*data_fp;

void
ftp_connect(struct url *url, int timeout)
{
	char	*buf = NULL;
	size_t	 n = 0;
	int	 sock;

	sock = tcp_connect(url->host, url->port, timeout);
	if ((ctrl_fp = fdopen(sock, "r+")) == NULL)
		err(1, "%s: fdopen", __func__);

	if (proxy)
		proxy_connect(url, ctrl_fp);

	/* greeting */
	if (ftp_getline(&buf, &n) != P_OK) {
		warnx("Can't connect to host `%s'", url->host);
		ftp_command("QUIT");
		exit(1);
	}

	free(buf);
	log_info("Connected to %s\n", url->host);
	/* TODO: read ~/.netrc for credentials */
	if (ftp_auth(NULL, NULL) != P_OK) {
		warnx("Can't login to host `%s'", url->host);
		ftp_command("QUIT");
		exit(1);
	}
}

struct url *
ftp_get(struct url *url)
{
	char	*dir;

	log_info("Using binary mode to transfer files.\n");
	if (ftp_command("TYPE I") != P_OK)
		errx(1, "Failed to set mode to binary");

	dir = dirname(url->path);
	if (ftp_command("CWD %s", dir) != P_OK)
		errx(1, "CWD command failed");

	if (url->offset &&
	    ftp_command("REST %lld", url->offset) != P_OK)
		errx(1, "REST command failed");

	if (ftp_size(url->fname, &url->file_sz) != P_OK)
		errx(1, "failed to get size of file %s", url->fname);

	/* TODO: EPSV */
	if ((data_fp = ftp_pasv()) == NULL)
		errx(1, "error retrieving file %s", url->fname);

	if (ftp_command("RETR %s", url->fname) != P_PRE)
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

	while ((r = fread(tmp_buf, 1, TMPBUF_LEN, data_fp)) != 0) {
		url->offset += r;
		if (fwrite(tmp_buf, 1, r, fp) != r)
			err(1, "%s: fwrite", __func__);
	}

	if (!feof(data_fp))
		errx(1, "%s: fread", __func__);

	fclose(fp);
	fclose(data_fp);
}

void
ftp_quit(struct url *url)
{
	char	*buf = NULL;
	size_t	 n = 0;

	if (ftp_getline(&buf, &n) != P_OK)
		errx(1, "error retrieving file %s", url->fname);

	free(buf);
	ftp_command("QUIT");
	fclose(ctrl_fp);
}

static int
ftp_getline(char **lineptr, size_t *n)
{
	ssize_t		 len;
	char		*bufp, code[4];
	const char	*errstr;
	int		 lookup[] = { P_PRE, P_OK, P_INTER, N_TRANS, N_PERM };


	if ((len = getline(lineptr, n, ctrl_fp)) == -1)
		err(1, "%s: getline", __func__);

	bufp = *lineptr;
	log_info("%s", bufp);
	if (len < 4)
		errx(1, "%s: line too short", __func__);

	(void)strlcpy(code, bufp, sizeof code);
	if (bufp[3] == ' ')
		goto done;

	/* multi-line reply */
	while (!(strncmp(code, bufp, 3) == 0 && bufp[3] == ' ')) {
		if ((len = getline(lineptr, n, ctrl_fp)) == -1)
			err(1, "%s: getline", __func__);

		bufp = *lineptr;
		log_info("%s", bufp);
		if (len < 4)
			continue;
	}

 done:
	(void)strtonum(code, 100, 553, &errstr);
	if (errstr)
		errx(1, "%s: Response code is %s: %s", __func__, errstr, code);

	return lookup[code[0] - '1'];
}

static int
ftp_command(const char *fmt, ...)
{
	va_list	 ap;
	char	*buf = NULL, *cmd;
	size_t	 n = 0;
	int	 r;

	va_start(ap, fmt);
	r = vasprintf(&cmd, fmt, ap);
	va_end(ap);
	if (r < 0)
		errx(1, "%s: vasprintf", __func__);

	if (http_debug)
		printf(">>> %s\n", cmd);

	if (fprintf(ctrl_fp, "%s\r\n", cmd) < 0)
		errx(1, "%s: fprintf", __func__);

	(void)fflush(ctrl_fp);
	free(cmd);
	r = ftp_getline(&buf, &n);
	free(buf);
	return r;

}

#define pack2(var, off) \
	(((var[(off) + 0] & 0xff) << 8) | ((var[(off) + 1] & 0xff) << 0))
#define pack4(var, off) \
	(((var[(off) + 0] & 0xff) << 24) | ((var[(off) + 1] & 0xff) << 16) | \
	 ((var[(off) + 2] & 0xff) << 8) | ((var[(off) + 3] & 0xff) << 0))

static FILE *
ftp_pasv(void)
{
	struct sockaddr_in	 sa;
	char			*buf = NULL, *s, *e;
	size_t			 n = 0;
	uint			 addr[4], port[2];
	int			 ret, sock;

	if (http_debug)
		printf(">>> PASV\n");

	if (fprintf(ctrl_fp, "PASV\r\n") < 0)
		errx(1, "%s: fprintf", __func__);

	(void)fflush(ctrl_fp);
	if (ftp_getline(&buf, &n) != P_OK) {
		free(buf);
		return NULL;
	}

	if ((s = strchr(buf, '(')) == NULL || (e = strchr(s, ')')) == NULL) {
		warnx("Malformed PASV reply");
		return NULL;
	}

	s++;
	*e = '\0';
	ret = sscanf(s, "%u,%u,%u,%u,%u,%u",
	    &addr[0], &addr[1], &addr[2], &addr[3],
	    &port[0], &port[1]);

	if (ret != 6) {
		warnx("Passive mode address scan failure");
		return NULL;
	}

	free(buf);
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_len = sizeof(sa);
	sa.sin_addr.s_addr = htonl(pack4(addr, 0));
	sa.sin_port = htons(pack2(port, 0));

	if ((sock = socket(sa.sin_family, SOCK_STREAM, 0)) == -1)
		err(1, "%s: socket", __func__);

	if (connect(sock, (struct sockaddr *)&sa, sa.sin_len) == -1)
		err(1, "%s: connect", __func__);

	return fdopen(sock, "r+");
}

static int
ftp_size(const char *fn, off_t *sizep)
{
	char	*buf = NULL;
	size_t	 n = 0;
	off_t	 file_sz;
	int	 code;

	if (http_debug)
		printf(">>> SIZE %s\n", fn);

	if (fprintf(ctrl_fp, "SIZE %s\r\n", fn) < 0)
		errx(1, "%s: fprintf", __func__);

	(void)fflush(ctrl_fp);
	if ((code = ftp_getline(&buf, &n)) != P_OK) {
		free(buf);
		return code;
	}

	if (sscanf(buf, "%*u %lld", &file_sz) != 1)
		errx(1, "%s: sscanf size", __func__);

	if (sizep)
		*sizep = file_sz;

	free(buf);
	return code;
}

static int
ftp_auth(const char *user, const char *pass)
{
	char	*addr = NULL, hn[MAXHOSTNAMELEN+1], *un;
	int	 code;

	code = ftp_command("USER %s", user ? user : "anonymous");
	if (code != P_OK && code != P_INTER)
		return code;

	if (pass == NULL) {
		if (gethostname(hn, sizeof hn) == -1)
			err(1, "%s: gethostname", __func__);

		un = getlogin();
		if (asprintf(&addr, "%s@%s", un ? un : "anonymous", hn) == -1)
			err(1, "%s: asprintf", __func__);
	}

	code = ftp_command("PASS %s", pass ? pass : addr);
	free(addr);
	return code;
}
