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
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>

#include "http.h"

#define	DEFAULT_CA_FILE	"/etc/ssl/cert.pem"
#define MAX_REDIRECTS	10

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
	char	*location;
	off_t	 content_length;
};

static struct http_headers	*headers_parse(int);
static void			 headers_free(struct http_headers *);
static void			 http_close(struct url *);
static const char		*http_error(int);
static struct url		*http_redirect(struct url *, char *);
static int			 http_status_code(const char *);
static int			 http_status_cmp(const void *, const void *);
static int			 http_request(int, struct http_headers **,
				    const char *, ...)
				    __attribute__((__format__ (printf, 3, 4)))
				    __attribute__((__nonnull__ (3)));
static ssize_t			 tls_getline(char **, size_t *, struct tls *);
static char			*relative_path_resolve(const char *,
				    const char *);

static struct tls_config	*tls_config;
static struct tls		*ctx;
static FILE			*fp;

static char * const		 tls_verify_opts[] = {
#define HTTP_TLS_CAFILE		0
	"cafile",
#define HTTP_TLS_CAPATH		1
	"capath",
#define HTTP_TLS_CIPHERS	2
	"ciphers",
#define HTTP_TLS_DONTVERIFY	3
	"dont",
#define HTTP_TLS_VERIFYDEPTH	4
	"depth",
#define HTTP_TLS_PROTOCOLS	5
	"protocols",
#define HTTP_TLS_MUSTSTAPLE	6
	"muststaple",
#define HTTP_TLS_NOVERIFYTIME	7
	"noverifytime",
	NULL
};

void
https_init(void)
{
	char		*str;
	int		 depth;
	uint32_t	 http_tls_protocols;
	const char	*ca_file = DEFAULT_CA_FILE, *errstr;

	if (tls_init() != 0)
		errx(1, "tls_init failed");

	if ((tls_config = tls_config_new()) == NULL)
		errx(1, "tls_config_new failed");

	while (tls_options && *tls_options) {
		switch (getsubopt(&tls_options, tls_verify_opts, &str)) {
		case HTTP_TLS_CAFILE:
			if (str == NULL)
				errx(1, "missing CA file");
			ca_file = str;
			break;
		case HTTP_TLS_CAPATH:
			if (str == NULL)
				errx(1, "missing ca path");
			if (tls_config_set_ca_path(tls_config, str) != 0)
				errx(1, "tls ca path failed");
			break;
		case HTTP_TLS_CIPHERS:
			if (str == NULL)
				errx(1, "missing cipher list");
			if (tls_config_set_ciphers(tls_config, str) != 0)
				errx(1, "tls set ciphers failed");
			break;
		case HTTP_TLS_DONTVERIFY:
			tls_config_insecure_noverifycert(tls_config);
			tls_config_insecure_noverifyname(tls_config);
			break;
		case HTTP_TLS_PROTOCOLS:
			if (tls_config_parse_protocols(&http_tls_protocols,
			    str) != 0)
				errx(1, "tls parsing protocols failed");
			tls_config_set_protocols(tls_config,
			    http_tls_protocols);
			break;
		case HTTP_TLS_VERIFYDEPTH:
			if (str == NULL)
				errx(1, "missing depth");
			depth = strtonum(str, 0, INT_MAX, &errstr);
			if (errstr)
				errx(1, "Cert validation depth is %s", errstr);
			tls_config_set_verify_depth(tls_config, depth);
			break;
		case HTTP_TLS_MUSTSTAPLE:
			tls_config_ocsp_require_stapling(tls_config);
			break;
		case HTTP_TLS_NOVERIFYTIME:
			tls_config_insecure_noverifytime(tls_config);
			break;
		default:
			errx(1, "Unknown -S suboption `%s'",
			    suboptarg ? suboptarg : "");
		}
	}

	if (tls_config_set_ca_file(tls_config, ca_file) == -1)
		errx(1, "tls_config_set_ca_file failed");
}

void
http_connect(struct url *url, int timeout)
{
	int	sock;

	sock = tcp_connect(url->host, url->port, timeout);
	if ((fp = fdopen(sock, "r+")) == NULL)
		err(1, "%s: fdopen", __func__);

	if (proxy)
		proxy_connect(url, fp);

	if (url->scheme == S_HTTP)
		return;

	if ((ctx = tls_client()) == NULL)
		errx(1, "failed to create tls client");

	if (tls_configure(ctx, tls_config) != 0)
		errx(1, "%s: %s", __func__, tls_error(ctx));

	if (tls_connect_socket(ctx, sock, url->host) != 0)
		errx(1, "%s: %s", __func__, tls_error(ctx));
}

void
proxy_connect(struct url *url, FILE *proxy_fp)
{
	int	code;

	code = http_request(url->scheme, NULL,
	    "CONNECT %s:%s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "\r\n",
	    url->host,
	    url->port,
	    url->host,
	    ua);

	if (code != 200)
		errx(1, "%s: failed to CONNECT to %s:%s: %s",
		    __func__, url->host, url->port, http_error(code));
}

struct url *
http_get(struct url *url)
{
	struct http_headers	*headers;
	char			*range;
	int			 code, redirects = 0;

 redirected:
	if (asprintf(&range, "Range: bytes=%lld-\r\n", url->offset) == -1)
		err(1, "%s: asprintf", __func__);

	code = http_request(url->scheme, &headers,
	    "GET %s HTTP/1.0\r\n"
	    "Host: %s\r\n"
	    "User-Agent: %s\r\n"
	    "%s"
	    "\r\n",
	    url->path ? url->path : "/",
	    url->host,
	    ua,
	    url->offset ? range : "");
	free(range);

	switch (code) {
	case 200:
		if (url->offset)
			warnx("Server does not support resume.");
		url->offset = 0;
		break;
	case 206:
		break;
	case 301:
	case 302:
	case 303:
	case 307:
		http_close(url);
		if (++redirects > MAX_REDIRECTS)
			errx(1, "Too many redirections requested");

		url = http_redirect(url, headers->location);
		headers_free(headers);
		log_request("Redirected to", url);
		http_connect(url, 0);
		log_request("Requesting", url);
		goto redirected;
	case 416:
		warnx("File is already fully retrieved");
		break;
	default:
		errx(1, "Error retrieving file: %d %s", code, http_error(code));
	}

	url->file_sz = headers->content_length + url->offset;
	headers_free(headers);
	return url;
}

static struct url *
http_redirect(struct url *old_url, char *location)
{
	struct url	*new_url;
	const char	*http, *https;

	http = scheme_str[S_HTTP];
	https = scheme_str[S_HTTPS];

	if (strncasecmp(location, http, strlen(http)) == 0 ||
	    strncasecmp(location, https, strlen(https)) == 0) {
		/* absolute uri reference */
		new_url = url_parse(location);
		if (old_url->scheme == S_HTTPS && new_url->scheme != S_HTTPS)
			errx(1, "aborting HTTPS to HTTP redirect");
	} else {
		/* relative uri reference */
		if ((new_url = calloc(1, sizeof *new_url)) == NULL)
			err(1, "%s: calloc", __func__);

		new_url->scheme = old_url->scheme;
		new_url->host = xstrdup(old_url->host, __func__);
		new_url->port = xstrdup(old_url->port, __func__);

		 /* absolute-path reference */
		if (location[0] == '/')
			new_url->path = xstrdup(location, __func__);
		else {
			new_url->path = relative_path_resolve(old_url->path,
			    location);
		}
	}

	new_url->fname = xstrdup(old_url->fname, __func__);
	url_free(old_url);
	return new_url;
}

static char *
relative_path_resolve(const char *base_path, const char *location)
{
	char	*new_path, *p;

	if (base_path == NULL) {
		if (asprintf(&new_path, "/%s", base_path) == -1)
			err(1, "%s: asprintf", __func__);
	} else if (base_path[strlen(base_path) - 1] == '/') {
		if (asprintf(&new_path, "%s%s", base_path, location) == -1)
			err(1, "%s: asprintf", __func__);
	} else {
		p = dirname(base_path);
		if (asprintf(&new_path, "%s/%s",
		    strcmp(p, ".") == 0 ? "" : p, location) == -1)
			err(1, "%s: asprintf", __func__);
	}

	return new_path;
}

void
http_save(struct url *url, int fd)
{
	FILE	*dst_fp;
	char	*tmp_buf;
	ssize_t	 r;

	if ((dst_fp = fdopen(fd, "w")) == NULL)
		err(1, "%s: fdopen", __func__);

	if (url->scheme == S_HTTP) {
		copy_file(url, fp, dst_fp);
		goto done;
	}

	if ((tmp_buf = malloc(TMPBUF_LEN)) == NULL)
		err(1, "%s: malloc", __func__);

	for (;;) {
		do {
			r = tls_read(ctx, tmp_buf, TMPBUF_LEN);
		} while (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT);

		if (r == -1)
			err(1, "%s: tls_read: %s", __func__, tls_error(ctx));
		else if (r == 0)
			break;

		url->offset += r;
		if (fwrite(tmp_buf, 1, r, dst_fp) != r)
			err(1, "%s: fwrite", __func__);
	}
	free(tmp_buf);

 done:
 	fclose(dst_fp);
	http_close(url);
}

static void
http_close(struct url *url)
{
	ssize_t	r;

	if (url->scheme == S_HTTPS) {
		do {
			r = tls_close(ctx);
		} while (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT);
		tls_free(ctx);
	}

	fclose(fp);
}

static int
http_request(int scheme, struct http_headers **headers, const char *fmt, ...)
{
	va_list	 ap;
	char	*req, *buf = NULL;
	size_t	 n = 0;
	ssize_t	 nw;
	int	 code, r;

	va_start(ap, fmt);
	r = vasprintf(&req, fmt, ap);
	va_end(ap);
	if (r < 0)
		err(1, "%s: vasprintf", __func__);

	if (http_debug)
		printf("<<< %s\n", req);

	if (scheme == S_HTTP) {
		if (fprintf(fp, "%s\r\n", req) < 0)
			errx(1, "%s: fprintf", __func__);
		(void)fflush(fp);
		if (getline(&buf, &n, fp) == -1)
			err(1, "%s: getline", __func__);
	} else {
		do {
			nw = tls_write(ctx, req, r);
		} while (nw == TLS_WANT_POLLIN || nw == TLS_WANT_POLLOUT);
		if (nw == -1)
			errx(1, "%s: tls_write", __func__);
		if (tls_getline(&buf, &n, ctx) == -1)
			errx(1, "%s: tls_getline", __func__);
	}

	free(req);
	if (http_debug)
		printf(">>> %s", buf);

	if ((code = http_status_code(buf)) == -1)
		errx(1, "%s: failed to extract status code", __func__);

	free(buf);
	if (headers != NULL)
		*headers = headers_parse(scheme);

	return code;
}

static int
http_status_code(const char *status_line)
{
	unsigned int	code;

	if (sscanf(status_line, "%*s %u %*s", &code) != 1)
		errx(1, "%s: failed to extract status code", __func__);

	if (code < 100 || code > 511)
		errx(1, "%s: invalid status code %d", __func__, code);

	return code;
}

static struct http_headers *
headers_parse(int scheme)
{
	struct http_headers	*headers;
	char			*buf = NULL, *p;
	const char		*errstr;
	size_t			 n = 0;
	ssize_t			 buflen;

	if ((headers = calloc(1, sizeof *headers)) == NULL)
		err(1, "%s: calloc", __func__);

	for (;;) {
		if (scheme == S_HTTP) {
			if ((buflen = getline(&buf, &n, fp)) == -1)
				err(1, "%s: getline", __func__);
		} else {
			if ((buflen = tls_getline(&buf, &n, ctx)) == -1)
				errx(1, "%s: tls_getline", __func__);
		}

		buf[buflen - 1] = '\0';
		buflen -= 1;
		if (buflen > 0 && buf[buflen - 1] == '\r') {
			buf[buflen - 1] = '\0';
			buflen -= 1;
		}

		if (http_debug)
			printf(">>> %s\n", buf);

		if (buflen == 0)
			break; /* end of headers */

		if (strncasecmp(buf, "Content-Length: ", 16) == 0) {
			if ((p = strchr(buf, ' ')) == NULL)
				errx(1, "Failed to parse Content-Length");

			p++;
			headers->content_length = strtonum(p, 0,
			    INT64_MAX, &errstr);
			if (errstr)
				err(1, "%s: Content Length is %s: %lld",
				    __func__, errstr, headers->content_length);
		}

		if (strncasecmp(buf, "Location: ", 10) == 0) {
			if ((p = strchr(buf, ' ')) == NULL)
				errx(1, "Failed to parse Location");

			headers->location = xstrdup(++p, __func__);
		}

	}

	free(buf);
	return headers;
}

static void
headers_free(struct http_headers *headers)
{
	if (headers == NULL)
		return;

	free(headers->location);
	free(headers);
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

#define MINBUF	128
static ssize_t
tls_getline(char **buf, size_t *buflen, struct tls *tls)
{
	char		*newb;
	size_t		 newlen, off;
	int		 ret;
	unsigned char	 c;

	if (buf == NULL || buflen == NULL) {
		/* tls_set_errorx(tls, "invalid arguments"); */
		return -1;
	}

	/* If buf is NULL, we have to assume a size of zero */
	if (*buf == NULL)
		*buflen = 0;

	off = 0;
	do {
		do {
			ret = tls_read(tls, &c, 1);
		} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);
		if (ret == -1)
			return -1;

		/* Ensure we can handle it */
		if (off + 2 > SSIZE_MAX) {
			/* tls_set_errorx(tls, "overflow"); */
			return -1;
		}

		newlen = off + 2; /* reserve space for NUL terminator */
		if (newlen > *buflen) {
			newlen = newlen < MINBUF ? MINBUF : *buflen * 2;
			newb = recallocarray(*buf, *buflen, newlen, 1);
			if (newb == NULL) {
				/* tls_set_error(tls, "reallocarray"); */
				return -1;
			}
			*buf = newb;
			*buflen = newlen;
		}

		*(*buf + off) = c;
		off += 1;
 	} while (c != '\n');

	*(*buf + off) = '\0';
	return off;
}
