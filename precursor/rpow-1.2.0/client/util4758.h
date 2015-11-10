/*
 * util4758.h
 *	General utility functions for dealing with 4758 data
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

#ifndef UTIL4758_H
#define UTIL4758_H

#include <sys/types.h>

#include <openssl/rsa.h>
#include "scc.h"

/* Don't know how portable this will be... */

#if (defined(__BYTE_ORDER) && (__BYTE_ORDER == __LITTLE_ENDIAN))  ||  defined(_LITTLE_ENDIAN)
/* The host byte order is the same as 4758 byte order,
   so these functions are all just identity.  */
# define scctohl(x)       (x)
# define scctohs(x)       (x)
# define htosccl(x)       (x)
# define htosccs(x)       (x)
#else
# if defined(__BYTE_ORDER) && (__BYTE_ORDER == __BIG_ENDIAN)
#  define scctohl(x)      bswap_32 (x)
#  define scctohs(x)      bswap_16 (x)
#  define htosccl(x)      bswap_32 (x)
#  define htosccs(x)      bswap_16 (x)
# else
#  ifdef _BIG_ENDIAN
#    define scctohl(x)      ((((x)>>24)&0xff)|(((x)>>8)&0xff00)|(((x)&0xff00)<<8)|(((x)&0xff)<<24))
#    define scctohs(x)      ((((x)>>8)&0xff)|(((x)&0xff)<<8))
#    define htosccl(x)      scctohl (x)
#    define htosccs(x)      scctohs (x)
#  else
	/* Cannot determine endianness, do it as a call */
	extern unsigned long _scctohl(unsigned long x);
	extern unsigned long _htosccl(unsigned long x);
	extern unsigned short _scctohs(unsigned short x);
	extern unsigned short _htosccs(unsigned short x);
#	define scctohl(x)		_scctohl(x)
#	define htosccl(x)		_htosccl(x)
#	define scctohs(x)		_scctohs(x)
#	define htosccs(x)		_htosccs(x)
#  endif
# endif
#endif

RSA *rsafrom4758 (sccRSAKey_t *tok);
RSA * rsafrombuf(unsigned char *keybuf, unsigned long keybuflen, int index);
unsigned char * keyptrfrombuf(unsigned long *klen, unsigned char *keybuf,
	unsigned long keybuflen, int index);


#endif
