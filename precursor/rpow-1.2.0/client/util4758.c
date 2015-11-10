/*
 * util4758.c
 * General utility functions for dealing with 4758 data.
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

#include <assert.h>
#include "util4758.h"

#if defined(_WIN32)
#define ntohl(x) ((((x)>>24)&0xff)|(((x)>>8)&0xff00)| \
					(((x)&0xff00)<<8)|(((x)&0xff)<<24))
#define htonl	ntohl
#endif

static union {
	int	i;
	unsigned char uc[4];
} endtest = {1};

#define UTIL4758_BIGENDIAN	(endtest.uc[3] == 1)
#define UTIL4758_LITTLEENDIAN	(endtest.uc[0] == 1)
#define TESTENDIAN			assert (UTIL4758_BIGENDIAN || UTIL4758_LITTLEENDIAN)

unsigned long
_scctohl(unsigned long x)
{
	TESTENDIAN;
	if (UTIL4758_LITTLEENDIAN)
		return x;
	return (((x)>>24)&0xff)|(((x)>>8)&0xff00)|(((x)&0xff00)<<8)|(((x)&0xff)<<24);
}
unsigned long
_htosccl(unsigned long x)
{
	TESTENDIAN;
	if (UTIL4758_LITTLEENDIAN)
		return x;
	return (((x)>>24)&0xff)|(((x)>>8)&0xff00)|(((x)&0xff00)<<8)|(((x)&0xff)<<24);
}
unsigned short
_scctohs(unsigned short x)
{
	TESTENDIAN;
	if (UTIL4758_LITTLEENDIAN)
		return x;
	return (((x)>>8)&0xff)|(((x)&0xff)<<8);
}
unsigned short
_htosccs(unsigned short x)
{
	TESTENDIAN;
	if (UTIL4758_LITTLEENDIAN)
		return x;
	return (((x)>>8)&0xff)|(((x)&0xff)<<8);
}

/* Convert an RSA public key from 4758 format to openssl format */
RSA *
rsafrom4758 (sccRSAKey_t *tok)
{
	RSA *rsa = RSA_new();
	unsigned off, len;

	off = scctohl(tok->n_Offset);
	len = scctohl(tok->n_Length);
	rsa->n = BN_bin2bn ((unsigned char *)tok + off, len, NULL);

	off = scctohl(tok->e_Offset);
	len = scctohl(tok->e_Length);
	rsa->e = BN_bin2bn ((unsigned char *)tok + off, len, NULL);
	return rsa;
}


/* Extract an RSA key from the buffer the card embeds in the cert chain */
/* Keys are stored as (n, e) pairs with each bignum preceded by 4 byte len */
RSA *
rsafrombuf(unsigned char *keybuf, unsigned long keybuflen, int index)
{
	RSA *rsa = RSA_new();
	unsigned long kblen;
	unsigned len;

	/* Skip to the nth entry */
	keybuf = keyptrfrombuf(&kblen, keybuf, keybuflen, index);

	if (kblen < sizeof(unsigned))
		return NULL;
	len = ntohl (*(unsigned *)keybuf);
	rsa->n = BN_bin2bn (keybuf+sizeof(unsigned), len, NULL);
	keybuf += len + sizeof(unsigned);
	kblen -= len + sizeof(unsigned);
	if (kblen < sizeof(unsigned))
		return NULL;
	len = ntohl (*(unsigned *)keybuf);
	rsa->e = BN_bin2bn (keybuf+sizeof(unsigned), len, NULL);
	keybuf += len + sizeof(unsigned);
	kblen -= len + sizeof(unsigned);
	if (kblen < 0)
		return NULL;

	return rsa;
}

/*
 * Find pointer to nth RSA key in the buffer the card embeds in the
 * cert chain.
 * Keys are stored as (n, e) pairs with each bignum preceded by 4 byte len
 */
unsigned char *
keyptrfrombuf(unsigned long *klen, unsigned char *keybuf,
	unsigned long keybuflen, int index)
{
	int kblen = keybuflen;
	unsigned len;

	/* Skip as needed */
	while (index-- > 0)
	{
		if (kblen < sizeof(unsigned))
			return NULL;
		len = ntohl (*(unsigned *)keybuf);
		keybuf += len + sizeof(unsigned);
		kblen -= len + sizeof(unsigned);
		if (kblen < sizeof(unsigned))
			return NULL;
		len = ntohl (*(unsigned *)keybuf);
		keybuf += len + sizeof(unsigned);
		kblen -= len + sizeof(unsigned);
	}

	if (klen)
		*klen = kblen;
	return keybuf;
}
