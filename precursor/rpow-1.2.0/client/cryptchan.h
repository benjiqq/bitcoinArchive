/*
 * cryptchan.h
 *	Header file for secure channel to 4758.
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
#ifndef CRYPTCHAN_H
#define CRYPTCHAN_H

#include <openssl/rsa.h>

/* Host side secure channel to IBM 4758 */

#define TDESBYTES		8
#define TDESKEYBYTES	24
#define RSAKEYBYTES		128
#define RSAKEYBITS		(8*RSAKEYBYTES)
#define SHABYTES		20
#define SEQNOBYTES		8

struct encstate {
	unsigned char tdeskeyin[TDESKEYBYTES];
	unsigned char tdeskeyout[TDESKEYBYTES];
	unsigned char hmackeyin[SHABYTES];
	unsigned char hmackeyout[SHABYTES];
	unsigned char seqnoin[SEQNOBYTES];
	unsigned char seqnoout[SEQNOBYTES];
	int failed;
};


/* Functions for general buffers */
int encryptmaster (struct encstate *encdata, RSA *rsa,
	unsigned char **outbuf, unsigned long *outbuflen);
int decryptinput (unsigned char **buf, unsigned long *buflen,
	struct encstate *encdata, unsigned char *inbuf, unsigned long inbuflen);
int encryptoutput (struct encstate *encdata, unsigned char *buf,
	unsigned long buflen, unsigned char **outbuf, unsigned long *outbuflen);

#endif
