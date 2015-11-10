/*
 * rpio.c
 *	Low level I/O for rpow package
 *
 * Copyright (C) 2004 Hal Finney
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>

#include "rpowcli.h"

#if defined(_WIN32)
#define ntohl(x) ((((x)>>24)&0xff)|(((x)>>8)&0xff00)| \
					(((x)&0xff00)<<8)|(((x)&0xff)<<24))
#define htonl	ntohl
#endif


static rpowio *
rp_newx  (FILE *f, BIO *bio)
{
	rpowio *rp = malloc (sizeof(rpowio));
	rp->f = f;
	rp->bio = bio;
	return rp;
}

rpowio *
rp_new_from_file (FILE *f)
{
	return rp_newx (f, NULL);
}

rpowio *
rp_new_from_bio (BIO *bio)
{
	return rp_newx (NULL, bio);
}

rpowio *
rp_new_from_buf (unsigned char *buf, unsigned buflen)
{
	BIO *bio = BIO_new(BIO_s_mem());
	rpowio *rpio = rp_new_from_bio (bio);
	BIO_write (bio, buf, buflen);
	return rpio;
}


void
rp_free (rpowio *rp)
{
	if (rp->bio)
		BIO_free (rp->bio);
	free (rp);
}

int
rp_write (rpowio *rp, void *buf, unsigned len)
{
	if (rp->f != NULL)
		return fwrite (buf, 1, len, rp->f);
	else if (rp->bio != NULL)
		return BIO_write (rp->bio, buf, len);
	else
		assert (0);
}

int
rp_read (rpowio *rp, void *buf, unsigned len)
{
	if (rp->f != NULL)
		return fread (buf, 1, len, rp->f);
	else if (rp->bio != NULL)
		return BIO_read (rp->bio, buf, len);
	else
		assert (0);
}


/* gbignum I/O */

int
bnwrite (gbignum *bn, rpowio *rpio)
{
	unsigned char *p;
	int len;
	int nlen;

	len = gbig_buflen (bn);
	p = malloc (len);
	gbig_to_buf (p, bn);
	nlen = htonl(len);
	if (rp_write (rpio, &nlen, sizeof(nlen)) != sizeof(nlen)
			|| rp_write (rpio, p, len) != len)
	{
		return -1;
	}
	free (p);
	return 0;
}

int
bnread (gbignum *bn, rpowio *rpio)
{
	unsigned char *p;
	int len;

	if (rp_read (rpio, &len, 4) != 4)
		return -1;
	len = ntohl(len);
	if (len > 0x1000)
		return -1;

	p = malloc (len);
	if (p==NULL)
		return -1;
	if (rp_read (rpio, p, len) != len)
		return -1;
	gbig_from_buf (bn, p, len);
	free (p);
	return 0;
}
