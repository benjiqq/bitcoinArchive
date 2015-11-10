/*
 * b64.c
 * Base64 encoding and decoding, concise.
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


static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int	/* outlen */
enc64 (char *out, unsigned char *in, int inlen)
{
	unsigned char c;
	unsigned char pc = 0;
	int st = 0;	/* counts 0, 2, 4 */
	char *iout = out;

	while (inlen--)
	{
		c = *in++;
		*out++ = cb64[pc | (c >> (2+st))];
		pc = (c << (4-st)) & 0x3f;
		if ((st+=2) == 6)
		{
			*out++ = cb64[pc];
			pc = st = 0;
		}
	}
	if (st > 0)
	{
		*out++ = cb64[pc];
		*out++ = '=';
		if (st == 2)
			*out++ = '=';
	}
	return out - iout;
}

static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

int	/* outlen */
dec64 (unsigned char *out, char *in, int inlen)
{
	unsigned char c;
	unsigned char pc = 0;
	int st = 0;	/* Counts 0, 2, 4, 6 */
	unsigned char *iout = out;

	while (inlen--)
	{
		c = (unsigned char)*in++;
		c = (c < '+' || c > 'z') ? '$' : cd64[c - '+'];
		if( c == '$')
			continue;
		c = c - 62;
		if (st > 0)
			*out++ = pc | (c >> (6-st));
		pc = c << (2+st);
		if ((st+=2) == 8)
			pc = st = 0;
	}
	/* assert (pc == 0); */
	return out - iout;
}

#if B64TEST

/* Test the above */
#include <stdio.h>
#include <stdlib.h>

typedef unsigned char uchar;

int
main (int ac, char **av)
{
	int decode = 0;
	int ibufsize, ibuflen, obuflen;
	uchar *ibuf, *obuf;

	if (ac > 1 && 0==strcmp(av[1], "-d"))
		decode = 1;

	ibufsize = 1000;
	ibuf = malloc (ibufsize);
	ibuflen = 0;
	for ( ; ; )
	{
		int nr = fread (ibuf+ibuflen, 1, ibufsize-ibuflen, stdin);
		ibuflen += nr;
		if (ibuflen < ibufsize)
			break;
		ibuf = realloc (ibuf, 2*ibufsize);
		ibufsize *= 2;
	}

	if (decode)
	{
		obuf = malloc (ibuflen);
		obuflen = dec64 (obuf, ibuf, ibuflen);
	} else {
		obuf = malloc (2*obuflen);
		obuflen = enc64 (obuf, ibuf, ibuflen);
	}

	fwrite (obuf, 1, obuflen, stdout);
	if (!decode)
		putchar ('\n');
}
#endif
