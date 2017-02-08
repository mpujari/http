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

#include <err.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http.h"

#define MAX_REDIRECTS 10

/*
 * HTTP status codes based on IANA assignments (2014-06-11 version):
 * https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
 * plus legacy (306) and non-standard (420).
 */
struct http_status {
	int		 code;
	const char	*name;
} http_status[] = {
	{ 100,	"Continue" },
	{ 101,	"Switching Protocols" },
	{ 102,	"Processing" },
	/* 103-199 unassigned */
	{ 200,	"OK" },
	{ 201,	"Created" },
	{ 202,	"Accepted" },
	{ 203,	"Non-Authoritative Information" },
	{ 204,	"No Content" },
	{ 205,	"Reset Content" },
	{ 206,	"Partial Content" },
	{ 207,	"Multi-Status" },
	{ 208,	"Already Reported" },
	/* 209-225 unassigned */
	{ 226,	"IM Used" },
	/* 227-299 unassigned */
	{ 300,	"Multiple Choices" },
	{ 301,	"Moved Permanently" },
	{ 302,	"Found" },
	{ 303,	"See Other" },
	{ 304,	"Not Modified" },
	{ 305,	"Use Proxy" },
	{ 306,	"Switch Proxy" },
	{ 307,	"Temporary Redirect" },
	{ 308,	"Permanent Redirect" },
	/* 309-399 unassigned */
	{ 400,	"Bad Request" },
	{ 401,	"Unauthorized" },
	{ 402,	"Payment Required" },
	{ 403,	"Forbidden" },
	{ 404,	"Not Found" },
	{ 405,	"Method Not Allowed" },
	{ 406,	"Not Acceptable" },
	{ 407,	"Proxy Authentication Required" },
	{ 408,	"Request Timeout" },
	{ 409,	"Conflict" },
	{ 410,	"Gone" },
	{ 411,	"Length Required" },
	{ 412,	"Precondition Failed" },
	{ 413,	"Payload Too Large" },
	{ 414,	"URI Too Long" },
	{ 415,	"Unsupported Media Type" },
	{ 416,	"Range Not Satisfiable" },
	{ 417,	"Expectation Failed" },
	{ 418,	"I'm a teapot" },
	/* 419-421 unassigned */
	{ 420,	"Enhance Your Calm" },
	{ 422,	"Unprocessable Entity" },
	{ 423,	"Locked" },
	{ 424,	"Failed Dependency" },
	/* 425 unassigned */
	{ 426,	"Upgrade Required" },
	/* 427 unassigned */
	{ 428,	"Precondition Required" },
	{ 429,	"Too Many Requests" },
	/* 430 unassigned */
	{ 431,	"Request Header Fields Too Large" },
	/* 432-450 unassigned */
	{ 451,	"Unavailable For Legal Reasons" },
	/* 452-499 unassigned */
	{ 500,	"Internal Server Error" },
	{ 501,	"Not Implemented" },
	{ 502,	"Bad Gateway" },
	{ 503,	"Service Unavailable" },
	{ 504,	"Gateway Timeout" },
	{ 505,	"HTTP Version Not Supported" },
	{ 506,	"Variant Also Negotiates" },
	{ 507,	"Insufficient Storage" },
	{ 508,	"Loop Detected" },
	/* 509 unassigned */
	{ 510,	"Not Extended" },
	{ 511,	"Network Authentication Required" },
	/* 512-599 unassigned */
	{ 0,	NULL },
	};

struct http_headers {
	const char	*location;
	off_t		 content_length;
};

static void		 headers_parse(struct http_headers *, const char *);
static const char	*http_error(int);
static int		 http_status_code(const char *);
static int		 http_status_cmp(const void *, const void *);
static int		 http_request(struct http_headers *, const char *, ...)
			    __attribute__((__format__ (printf, 2, 3)))
			    __attribute__((__nonnull__ (2)));

static int	sock;

void
http_connect(struct url *url)
{
	if (url->port[0] == '\0')
		(void)strlcpy(url->port, "80", sizeof url->port);

	sock = tcp_connect(url->host, url->port);
	if (proxy)
		proxy_connect(url, sock);
}

void
proxy_connect(struct url *url, int fd)
{
	char	buf[MAX_LINE];

	writeline(fd,
	    "CONNECT %s:%s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s%s"
	    "\r\n",
	    url->host,
	    url->port,
	    url->host,
	    ua,
	    url->basic_auth[0] ? "Proxy-Authorization: Basic " : "",
	    url->basic_auth[0] ? url->basic_auth : "");

	if (readline(fd, buf, sizeof buf) <= 0)
		errx(1, "%s: Failed to get proxy response", __func__);

	if (http_status_code(buf) != 200)
		errx(1, "%s: Failed CONNECT to %s:%s\n", __func__,
		    url->host, url->port);
}

void
http_get(struct url *url)
{
	static struct http_headers	headers;
	char				range[BUFSIZ], *str;
	int				code, redirects = 0;

 redirected:
	memset(&headers, 0, sizeof headers);
	(void)snprintf(range, sizeof range,
	    "Range: bytes=%lld-\r\n", url->offset);
	code = http_request(&headers,
	    "GET %s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s"
	    "%s%s"
	    "\r\n",
	    url->path ? url->path : "/",
	    url->host,
	    ua,
	    url->offset ? range : "",
	    url->basic_auth[0] ? "Authorization: Basic " : "",
	    url->basic_auth[0] ? url->basic_auth : "");

	switch (code) {
	case 200:
		/* Expected partial content but got full content */
		url->offset = 0;
		break;
	case 206:
		break;
	case 301:
	case 302:
	case 303:
	case 307:
		if (++redirects > MAX_REDIRECTS)
			errx(1, "Too many redirections requested");

		free((void *)url->path);
		if (headers.location[0] == '/')
			url->path = xstrdup(headers.location, __func__);
		else {
			str = url_encode(headers.location);
			url_parse(url, str);
			free(str);
		}

		log_info("Redirected to %s\n", headers.location);
		free((void *)headers.location);
		buffer_drain(-1);
		http_connect(url);
		log_request(url);
		goto redirected;
	case 416:
		warnx("File is already fully retrieved");
		break;
	default:
		errx(1, "Error retrieving file: %d %s", code, http_error(code));
	}

	url->file_sz = headers.content_length + url->offset;
	free((void *)headers.location);
}

void
http_save(struct url *url, int fd)
{
	FILE		*fp;
	ssize_t		 r;

	if ((fp = fdopen(fd, "w")) == NULL)
		err(1, "%s: fdopen", __func__);

	url->offset += buffer_drain(fd);
	while ((r = read(sock, tmp_buf, TMPBUF_LEN)) != 0) {
		if (r == -1)
			err(1, "%s: read", __func__);

		url->offset += r;
		if (fwrite(tmp_buf, r, 1, fp) != 1)
			err(1, "%s: fwrite", __func__);
	}

	fclose(fp);
}

static int
http_request(struct http_headers *headers, const char *fmt, ...)
{
	char	buf[MAX_LINE];
	va_list	ap;
	ssize_t	r;
	int	code;

	va_start(ap, fmt);
	r = vwriteline(sock, fmt, ap);
	va_end(ap);
	if (r == 0)
		errx(1, "%s: socket closed", __func__);

	if (readline(sock, buf, sizeof buf) <= 0)
		errx(1, "%s: Failed to get response", __func__);

	if ((code = http_status_code(buf)) == -1)
		errx(1, "%s: Failed to extract status code", __func__);

	do {
		r = readline(sock, buf, sizeof buf);
		if (r == -1)
			errx(1, "%s: readline failed", __func__);

		if (headers)
			headers_parse(headers, buf);
	} while (r != 0);

	return code;
}

static int
http_status_code(const char *status_line)
{
	const char	*errstr;
	char		 code[4], *p;
	int		 res;

	if ((p = strchr(status_line, ' ')) == NULL)
		errx(1, "%s: Malformed response: %s", __func__, status_line);

	p++;
	(void)strlcpy(code, p, sizeof code);
	res = strtonum(code, 200, 511, &errstr);
	if (errstr)
		errx(1, "%s: Response code is %s: %d", __func__, errstr, res);

	return res;
}

/* XXX key, value tree */
static void
headers_parse(struct http_headers *headers, const char *buf)
{
	const char	*errstr;
	size_t		 sz;

	if (strncasecmp(buf, "Content-Length: ", 16) == 0) {
		if ((buf = strchr(buf, ' ')) == NULL)
			errx(1, "Failed to parse Content-Length header");

		buf++;
		headers->content_length = strtonum(buf, 0, INT64_MAX, &errstr);
		if (errstr)
			err(1, "%s: Content Length is %s: %lld", __func__,
			    errstr, headers->content_length);
	}

	if (strncasecmp(buf, "Location: ", 10) == 0) {
		if ((buf = strchr(buf, ' ')) == NULL)
			errx(1, "Failed to parse Location header");

		headers->location = xstrdup(++buf, __func__);
	}
}

static const char *
http_error(int code)
{
	struct http_status	error, *res;

	/* Set up key */
	error.code = code;

	if ((res = bsearch(&error, http_status,
	    sizeof(http_status) / sizeof(http_status[0]) - 1,
	    sizeof(http_status[0]), http_status_cmp)) != NULL)
		return (res->name);

	return (NULL);
}

static int
http_status_cmp(const void *a, const void *b)
{
	const struct http_status *ea = a;
	const struct http_status *eb = b;

	return (ea->code - eb->code);
}
