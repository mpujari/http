/*
 * Copyright (c) 2015 Sunil Nimmagadda <sunil@openbsd.org>
 * Copyright (c) 2012 - 2015 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/types.h>

#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>

#define MAX_LINE	4096
#define TMPBUF_LEN	131072

#define	S_HTTP	0
#define S_HTTPS	1
#define S_FTP	2
#define S_FILE	3

struct tls;

struct url {
	char		 host[HOST_NAME_MAX+1];
	char		 port[NI_MAXSERV];
	char		 basic_auth[BUFSIZ];
	const char	*fname;
	const char	*path;
	off_t		 file_sz;
	off_t		 offset;
	int		 scheme;
};

/* ftp.c */
void	ftp_connect(struct url *, int);
void	ftp_get(struct url *);
void	ftp_save(struct url *, int);

/* http.c */
void	http_connect(struct url *, int);
void	http_get(struct url *);
void	http_save(struct url *, int);
void	https_init(void);

/* io.c */
ssize_t	buffer_drain(int);
ssize_t	readline(int, void *, size_t);
ssize_t	writeline(int, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)))
	    __attribute__((__nonnull__ (2)));
ssize_t	vwriteline(int, const char *, va_list);
ssize_t	tls_readline(struct tls *, char *, size_t);
ssize_t	tls_vwriteline(struct tls *, const char *, va_list);

/* main.c */
extern char		 tmp_buf[TMPBUF_LEN];
extern char		*tls_options;
extern const char	*ua;
extern struct url	*proxy;
extern int		 http_debug;

void	log_info(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)))
	    __attribute__((__nonnull__ (1)));
void	url_parse(struct url *, const char *);
void	log_request(struct url *);

/* progressmeter.c */
void	init_progress_meter(const char *, int);
void	start_progress_meter(const char *, off_t, off_t *);
void	stop_progress_meter(void);

/* util.c */
char	*url_encode(const char *);
int	 tcp_connect(const char *, const char *, int);
void	 proxy_connect(struct url *, int);
char	*xstrdup(const char *, const char *);
