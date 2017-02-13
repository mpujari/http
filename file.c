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

#include <sys/uio.h>
#include <sys/queue.h>

#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "http.h"

static int	src_fd;

void
file_connect(struct imsgbuf *ibuf, struct imsg *imsg, struct url *url)
{
	if ((src_fd = fd_request(ibuf, imsg, url->path, O_RDONLY)) == -1)
		errx(1, "%s: fd_request", __func__);
}

void
file_request(struct imsgbuf *ibuf, struct imsg *imsg, struct url *url)
{
	int	save_errno;

	url->file_sz = stat_request(ibuf, imsg, url->path, &save_errno);
	if (url->file_sz == -1) {
		errno = save_errno;
		err(1, "Can't open file %s", url->path);
	}
}

void
file_save(struct imsgbuf *ibuf, struct imsg *imsg, struct url *url, int dst_fd)
{
	FILE	*fp;
	ssize_t	 r;

	if ((fp = fdopen(dst_fd, "w")) == NULL)
		err(1, "%s: fdopen", __func__);

	/* XXX source is a file too, use stdio */
	while ((r = read(src_fd, tmp_buf, TMPBUF_LEN)) != 0) {
		if (r == -1)
			err(1, "%s: read", __func__);

		url->offset += r;
		if (fwrite(tmp_buf, r, 1, fp) != 1)
			err(1, "%s: fwrite", __func__);
	}

	fclose(fp);
	close(src_fd);
}
