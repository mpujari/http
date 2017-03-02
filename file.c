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

#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "http.h"

struct imsgbuf;
struct imsg;

static FILE	*src_fp;

void
file_connect(struct imsgbuf *ibuf, struct imsg *imsg, struct url *url)
{
	int	src_fd;

	if ((src_fd = fd_request(ibuf, imsg, url->path, O_RDONLY)) == -1)
		exit(1);

	if ((src_fp = fdopen(src_fd, "r")) == NULL)
		err(1, "%s: fdopen", __func__);
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
file_save(struct url *url, int dst_fd)
{
	FILE	*dst_fp;
	ssize_t	 r;

	if ((dst_fp = fdopen(dst_fd, "w")) == NULL)
		err(1, "%s: fdopen", __func__);

	while ((r = fread(tmp_buf, 1, TMPBUF_LEN, src_fp)) != 0) {
		url->offset += r;
		if (fwrite(tmp_buf, 1, r, dst_fp) != r)
			err(1, "%s: fwrite", __func__);
	}

	if (!feof(src_fp))
		errx(1, "%s: fread", __func__);

	fclose(dst_fp);
	fclose(src_fp);
}
