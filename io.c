/*
 * Copyright (c) 2017 Sunil Nimmagadda <sunil@openbsd.org>
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

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "http.h"

static char	rbuf[MAX_LINE], *rbuf_ptr;
static ssize_t	buflen;

static ssize_t	buffered_read(int, char *);
static ssize_t	tls_buffered_read(struct tls *, char *);
static ssize_t	readline_internal(struct tls *, int, void *buf, size_t);
static ssize_t	vwriteline_internal(struct tls *,int, const char *, va_list);

ssize_t
readline(int fd, void *buf, size_t len)
{
	return readline_internal(NULL, fd, buf, len);
}

ssize_t
tls_readline(struct tls *ctx, char *buf, size_t len)
{
	return readline_internal(ctx, -1, buf, len);
}

ssize_t
buffer_drain(int fd)
{
	ssize_t	 nwritten;
	char	*p;

	if (buflen == 0)
		return 0;

	/* reset buffer */
	if (fd == -1) {
		buflen = 0;
		return 0;
	}

	p = rbuf_ptr;
	while (buflen > 0) {
		nwritten = write(fd, p, buflen);
		switch (nwritten) {
		case -1:
			err(1, "%s: write", __func__);
		default:
			buflen -= nwritten;
			p += nwritten;
		}
	}

	return (p - rbuf_ptr);
}

static ssize_t
buffered_read(int fd, char *c)
{
	if (buflen <= 0) {
		buflen = read(fd, rbuf, sizeof rbuf);
		switch (buflen) {
		case -1:
			err(1, "read");
		case 0:
			return 0;
		default:
			rbuf_ptr = rbuf;
		}
	}

	buflen--;
	*c = *rbuf_ptr++;
	return 1;
}

static ssize_t
tls_buffered_read(struct tls *ctx, char *c)
{
	if (buflen <= 0) {
again:
		buflen = tls_read(ctx, rbuf, sizeof rbuf);
		switch (buflen) {
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			goto again;
		case -1:
			errx(1, "tls_read");
		case 0:
			return 0;
		default:
			rbuf_ptr = rbuf;
		}
	}

	buflen--;
	*c = *rbuf_ptr++;
	return 1;
}

static ssize_t
readline_internal(struct tls *ctx, int fd, void *buf, size_t len)
{
	ssize_t	n, nread;
	char	c = 0, *p;

	p = buf;
	for (n = 1; n < len; n++) {
		if (ctx)
			nread = tls_buffered_read(ctx, &c);
		else
			nread = buffered_read(fd, &c);

		switch (nread) {
		case 1:
			*p++ = c;
			if (c == '\n')
				goto done;
			break;
		case 0:
			return 0;
		default:
			return -1;
		}
	}

done:
	if (c != '\n')
		errx(1, "%s: Line too long", __func__);

	*p = '\0';
	if (http_debug)
		fprintf(stderr, ">>> %s", (char *)buf);

	/* strip \r\n */
	*(p - 1) = '\0';
	n--;
	if (*(p - 2) == '\r') {
		*(p - 2) = '\0';
		n--;
	}

	return n;
}

ssize_t
writeline(int fd, const char *fmt, ...)
{
	ssize_t	r;
	va_list	ap;

	va_start(ap, fmt);
	r = vwriteline(fd, fmt, ap);
	va_end(ap);
	return r;
}

ssize_t
tls_writeline(struct tls *ctx, const char *fmt, ...)
{
	ssize_t	r;
	va_list	ap;

	va_start(ap, fmt);
	r = tls_vwriteline(ctx, fmt, ap);
	va_end(ap);
	return r;
}

ssize_t
vwriteline(int fd, const char *fmt, va_list ap)
{
	return vwriteline_internal(NULL, fd, fmt, ap);
}

ssize_t
tls_vwriteline(struct tls *ctx, const char *fmt, va_list ap)
{
	return vwriteline_internal(ctx, -1, fmt, ap);
}

static ssize_t
vwriteline_internal(struct tls *ctx, int fd, const char *fmt, va_list ap)
{
	ssize_t	nwritten;
	size_t	nleft;
	int	n;
	char	buf[MAX_LINE], *p;

	n = vsnprintf(buf, sizeof buf, fmt, ap);
	if (n == -1)
		errx(1, "%s: vsnprintf failed", __func__);
	else if ( n >= MAX_LINE)
		errx(1, "%s: Line too long", __func__);

	if ((n = strlcat(buf, "\r\n", sizeof buf)) >= sizeof buf)
		errx(1, "%s: buffer overflow", __func__);

	if (http_debug)
		fprintf(stderr, "<<< %s", buf);

	p = buf;
	nleft = n;
	while (nleft > 0) {
		if (ctx) {
			do {
				nwritten = tls_write(ctx, p, nleft);
			} while (nwritten == TLS_WANT_POLLIN ||
			    nwritten == TLS_WANT_POLLOUT);
		} else
			nwritten = write(fd, p, nleft);

		switch (nwritten) {
		case -1:
			if (ctx)
				errx(1, "tls_write");
			else
				err(1, "write");
		case 0:
			return 0;
		default:
			nleft -= nwritten;
			p += nwritten;
		}
	}

	return n;
}
