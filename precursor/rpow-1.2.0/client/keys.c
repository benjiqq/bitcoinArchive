/*
 * keys.c
 *	Key related functions for RPOW package
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


/* Math functions */


/* I/O functions */

/* Compute keyid for pubkey */
static void
pk_to_keyid (pubkey *key, unsigned char *keyid)
{
	gbig_sha1ctx ctx;
	unsigned char *p;
	int len;
	int nlen;

	gbig_sha1_init (&ctx);

	len = gbig_buflen (&key->n);
	p = malloc (len);
	gbig_to_buf (p, &key->n);
	nlen = htonl(len);
	gbig_sha1_update (&ctx, &nlen, sizeof(nlen));
	gbig_sha1_update (&ctx, p, len);

	len = gbig_buflen (&key->e);
	p = realloc (p, len);
	gbig_to_buf (p, &key->e);
	nlen = htonl(len);
	gbig_sha1_update (&ctx, &nlen, sizeof(nlen));
	gbig_sha1_update (&ctx, p, len);

	gbig_sha1_final (keyid, &ctx);
	free (p);
}

void
pubkey_read (pubkey *key, char *file)
{
	rpowio *rpio;
	FILE *f = fopen (file, "rb");
	if (f == NULL)
	{
		fprintf (stderr, "Unable to open file %s for input\n", file);
		exit (1);
	}

	rpio = rp_new_from_file (f);

	gbig_init (&key->n);
	gbig_init (&key->e);

	if (bnread (&key->n, rpio) < 0
		|| bnread (&key->e, rpio) < 0
		|| rp_read (rpio, key->cardid, CARDID_LENGTH) != CARDID_LENGTH)
	{
		fprintf (stderr, "Error reading public key from file %s\n", file);
		exit (1);
	}
	fclose (f);
	rp_free (rpio);

	pk_to_keyid (key, key->keyid);
	key->state = PUBKEY_STATE_ACTIVE;
}

void
pubkey_write (pubkey *key, char *file)
{
	rpowio *rpio;
	FILE *f = fopen (file, "wb");
	if (f == NULL)
	{
		fprintf (stderr, "Unable to open file %s for output\n", file);
		exit (1);
	}

	rpio = rp_new_from_file (f);

	if (bnwrite (&key->n, rpio) < 0
		|| bnwrite (&key->e, rpio) < 0
		|| rp_write (rpio, key->cardid, CARDID_LENGTH) != CARDID_LENGTH)
	{
		fprintf (stderr, "Error writing public key to file %s\n", file);
		exit (1);
	}
	fclose (f);
	rp_free (rpio);
}
