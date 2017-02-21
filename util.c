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

/*-
 * Copyright (c) 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason Thorpe and Luke Mewburn.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <imsg.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "http.h"

static void	tooslow(int);
static int	unsafe_char(const char *);

/*
 * Encode given URL, per RFC1738.
 * Allocate and return string to the caller.
 */
char *
url_encode(const char *path)
{
	size_t i, length, new_length;
	char *epath, *epathp;

	length = new_length = strlen(path);

	/*
	 * First pass:
	 * Count unsafe characters, and determine length of the
	 * final URL.
	 */
	for (i = 0; i < length; i++)
		if (unsafe_char(path + i))
			new_length += 2;

	epath = epathp = malloc(new_length + 1);	/* One more for '\0'. */
	if (epath == NULL)
		err(1, "Can't allocate memory for URL encoding");

	/*
	 * Second pass:
	 * Encode, and copy final URL.
	 */
	for (i = 0; i < length; i++)
		if (unsafe_char(path + i)) {
			snprintf(epathp, 4, "%%" "%02x",
			    (unsigned char)path[i]);
			epathp += 3;
		} else
			*(epathp++) = path[i];

	*epathp = '\0';
	return epath;
}

/*
 * Determine whether the character needs encoding, per RFC1738:
 * 	- No corresponding graphic US-ASCII.
 * 	- Unsafe characters.
 */
static int
unsafe_char(const char *c0)
{
	const char *unsafe_chars = " <>\"#{}|\\^~[]`";
	const unsigned char *c = (const unsigned char *)c0;

	/*
	 * No corresponding graphic US-ASCII.
	 * Control characters and octets not used in US-ASCII.
	 */
	return (iscntrl(*c) || !isascii(*c) ||

	    /*
	     * Unsafe characters.
	     * '%' is also unsafe, if is not followed by two
	     * hexadecimal digits.
	     */
	    strchr(unsafe_chars, *c) != NULL ||
	    (*c == '%' && (!isxdigit(*++c) || !isxdigit(*++c))));
}

static void
tooslow(int signo)
{
	extern char	*__progname;

	dprintf(STDERR_FILENO, "%s: connect taking too long\n", __progname);
	_exit(2);
}

int
tcp_connect(const char *host, const char *port, int timeout)
{
	struct addrinfo	 hints, *res, *res0;
	char		 hbuf[NI_MAXHOST];
	const char	*cause = NULL;
	int		 error, s = -1, save_errno;

	if (proxy) {
		host = proxy->host;
		port = proxy->port;
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((error = getaddrinfo(host, port, &hints, &res0)))
		errx(1, "%s: %s", host, gai_strerror(error));

	if (timeout) {
		(void)signal(SIGALRM, tooslow);
		alarm(timeout);
	}

	for (res = res0; res; res = res->ai_next) {
		if (getnameinfo(res->ai_addr, res->ai_addrlen, hbuf,
		    sizeof hbuf, NULL, 0, NI_NUMERICHOST) != 0)
			(void)strlcpy(hbuf, "(unknown)", sizeof hbuf);

		log_info("Trying %s...\n", hbuf);
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			save_errno = errno;
			close(s);
			errno = save_errno;
			s = -1;
			continue;
		}

		break;
	}

	freeaddrinfo(res0);
	if (s == -1)
		err(1, "%s", cause);

	if (timeout) {
		signal(SIGALRM, SIG_DFL);
		alarm(0);
	}

	return s;
}

char *
xstrdup(const char *str, const char *where)
{
	char	*r;

	if ((r = strdup(str)) == NULL)
		errx(1, "%s: strdup", where);

	return r;
}

off_t
stat_request(struct imsgbuf *ibuf, struct imsg *imsg,
    const char *fname, int *save_errno)
{
	off_t	*poffset;
	size_t	 len;

	len = strlen(fname) + 1;
	send_message(ibuf, IMSG_STAT, -1, (char *)fname, len, -1);
	if (read_message(ibuf, imsg) == 0)
		return -1;

	if (imsg->hdr.type != IMSG_STAT)
		errx(1, "%s: IMSG_STAT expected", __func__);

	if ((imsg->hdr.len - IMSG_HEADER_SIZE) != sizeof(off_t))
		errx(1, "%s: imsg size mismatch", __func__);

	if (save_errno)
		*save_errno = imsg->hdr.peerid;

	poffset = imsg->data;
	return *poffset;
}

int
fd_request(struct imsgbuf *ibuf, struct imsg *imsg,
    const char *fname, int flags)
{
	struct open_req	req;

	if (strlcpy(req.fname, fname, sizeof req.fname) >= sizeof req.fname)
		errx(1, "%s: filename overflow", __func__);

	req.flags = flags;
	send_message(ibuf, IMSG_OPEN, -1, &req, sizeof req, -1);
	if (read_message(ibuf, imsg) == 0)
		return -1;

	if (imsg->hdr.type != IMSG_OPEN)
		errx(1, "%s: IMSG_OPEN expected", __func__);

	if (imsg->fd == -1)
		errx(1, "%s: expected a file descriptor", __func__);

	return imsg->fd;
}

void
send_message(struct imsgbuf *ibuf, int type, uint32_t peerid,
    void *msg, size_t msglen, int fd)
{
	if (imsg_compose(ibuf, type, peerid, 0, fd, msg, msglen) != 1)
		err(1, "imsg_compose");

	if (imsg_flush(ibuf) != 0)
		err(1, "imsg_flush");
}

int
read_message(struct imsgbuf *ibuf, struct imsg *imsg)
{
	int	n;

	if ((n = imsg_read(ibuf)) == -1)
		err(1, "imsg_read");
	if (n == 0)
		return 0;

	if ((n = imsg_get(ibuf, imsg)) == -1)
		err(1, "imsg_get");
	if (n == 0)
		return 0;

	return n;
}
