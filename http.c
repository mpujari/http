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
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

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

static void		 headers_parse(struct http_headers **, const char *);
static void		 headers_free(struct http_headers *);
static void		 http_close(struct url *);
static const char	*http_error(int);
static struct url	*http_redirect(struct url *, const char *);
static int		 http_status_code(const char *);
static int		 http_status_cmp(const void *, const void *);
static int		 http_request(int, struct http_headers **,
			    const char *, ...)
			    __attribute__((__format__ (printf, 3, 4)))
			    __attribute__((__nonnull__ (3)));

static struct tls_config	*tls_config;
static struct tls		*ctx;
static int			 sock;

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
	sock = tcp_connect(url->host, url->port, timeout);
	if (proxy)
		proxy_connect(url, sock);

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
proxy_connect(struct url *url, int fd)
{
	char	buf[MAX_LINE];
	int	code;

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
	    url->basic_auth ? "Proxy-Authorization: Basic " : "",
	    url->basic_auth ? url->basic_auth : "");

	if (readline(fd, buf, sizeof buf) <= 0)
		errx(1, "%s: Failed to get proxy response", __func__);

	if ((code = http_status_code(buf)) != 200)
		errx(1, "%s: Failed CONNECT to %s:%s: %s\n", __func__,
		    url->host, url->port, http_error(code));
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
	    "%s%s"
	    "\r\n",
	    url->path ? url->path : "/",
	    url->host,
	    ua,
	    url->offset ? range : "",
	    url->basic_auth ? "Authorization: Basic " : "",
	    url->basic_auth ? url->basic_auth : "");
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
		buffer_drain(-1);
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

struct url *
http_redirect(struct url *old_url, const char *url_str)
{
	struct url	*new_url;

	/* TODO: RFC 3986 #5.2 */
	if (url_str[0]== '/') {
		if ((new_url = calloc(1, sizeof *new_url)) == NULL)
			err(1, "%s: calloc", __func__);

		new_url->scheme = old_url->scheme;
		new_url->host = xstrdup(old_url->host, __func__);
		new_url->port = xstrdup(old_url->port, __func__);
		new_url->basic_auth = xstrdup(old_url->basic_auth, __func__);
		new_url->path = xstrdup(url_str, __func__);
	} else {
		new_url = url_parse(url_str);
		if (old_url->scheme == S_HTTPS && new_url->scheme != S_HTTPS)
			errx(1, "HTTPS to HTTP redirects not permitted");
	}

	new_url->fname = xstrdup(old_url->fname, __func__);
	url_free(old_url);
	return new_url;
}

void
http_save(struct url *url, int fd)
{
	FILE		*fp;
	ssize_t		 r;

	if ((fp = fdopen(fd, "w")) == NULL)
		err(1, "%s: fdopen", __func__);

	url->offset += buffer_drain(fd);
	while (1) {
		if (url->scheme == S_HTTP) {
			if ((r = read(sock, tmp_buf, TMPBUF_LEN)) == -1)
				err(1, "%s: read", __func__);
		} else {
 again:
			r = tls_read(ctx, tmp_buf, TMPBUF_LEN);
			switch (r) {
			case TLS_WANT_POLLIN:
			case TLS_WANT_POLLOUT:
				goto again;
			case -1:
				err(1, "tls_read: %s", tls_error(ctx));
			}
		}

		if (r == 0)
			break;

		url->offset += r;
		if (fwrite(tmp_buf, r, 1, fp) != 1)
			err(1, "%s: fwrite", __func__);
	}

 	fclose(fp);
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

	close(sock);
}

static int
http_request(int scheme, struct http_headers **headers, const char *fmt, ...)
{
	char	buf[MAX_LINE];
	va_list	ap;
	ssize_t	r;
	int	code;

	va_start(ap, fmt);
	if (scheme == S_HTTP)
		r = vwriteline(sock, fmt, ap);
	else
		r = tls_vwriteline(ctx, fmt, ap);
	va_end(ap);

	if (r == 0)
		errx(1, "%s: socket closed", __func__);

	if (scheme == S_HTTP)
		r = readline(sock, buf, sizeof buf);
	else
		r = tls_readline(ctx, buf, sizeof buf);

	if (r <= 0)
		errx(1, "%s: Failed to get response", __func__);

	if ((code = http_status_code(buf)) == -1)
		errx(1, "%s: Failed to extract status code", __func__);

	while (1) {
		if (scheme == S_HTTP)
			r = readline(sock, buf, sizeof buf);
		else
			r = tls_readline(ctx, buf, sizeof buf);

		if (r == -1)
			errx(1, "%s: readline failed", __func__);

		if (r == 0)
			break;

		headers_parse(headers, buf);
	}

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

/* XXX key, value tree */
static void
headers_parse(struct http_headers **headers, const char *buf)
{
	const char	*errstr;
	char		*location = NULL;
	off_t		 content_length = 0;

	if (strncasecmp(buf, "Content-Length: ", 16) == 0) {
		if ((buf = strchr(buf, ' ')) == NULL)
			errx(1, "Failed to parse Content-Length header");

		buf++;
		content_length = strtonum(buf, 0, INT64_MAX, &errstr);
		if (errstr)
			err(1, "%s: Content Length is %s: %lld", __func__,
			    errstr, content_length);
	}

	if (strncasecmp(buf, "Location: ", 10) == 0) {
		if ((buf = strchr(buf, ' ')) == NULL)
			errx(1, "Failed to parse Location header");

		location = xstrdup(++buf, __func__);
	}

	if ((*headers = malloc(sizeof **headers)) == NULL)
		err(1, "%s: malloc", __func__);

	(*headers)->content_length = content_length;
	(*headers)->location = location;
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
