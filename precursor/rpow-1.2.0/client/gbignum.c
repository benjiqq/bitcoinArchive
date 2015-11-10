/*
 * gbignum.c
 *	Generic bignum module implemented via OpenSSL
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
#include "gbignum.h"

BN_CTX *bnctx;

BIGNUM gbig_value_zero;
BIGNUM gbig_value_one;
BIGNUM gbig_value_two;
BIGNUM gbig_value_three;

int
gbig_initialize ()
{
	bnctx = BN_CTX_new();
	BN_init (&gbig_value_zero);
	BN_init (&gbig_value_one);
	BN_init (&gbig_value_two);
	BN_init (&gbig_value_three);
	BN_set_word (&gbig_value_one, 1);
	BN_set_word (&gbig_value_two, 2);
	BN_set_word (&gbig_value_three, 3);
	return 0;
}

int
gbig_finalize ()
{
	if (bnctx)
		BN_CTX_free (bnctx);
	BN_free (&gbig_value_zero);
	BN_free (&gbig_value_one);
	BN_free (&gbig_value_two);
	BN_free (&gbig_value_three);
	return 0;
}

/* Return number of bytes requested on success, less on failure */
int
gbig_rand_bytes (void *buf, unsigned len)
{
	if (RAND_bytes(buf, len) == 1)
		return len;
	return -1;
}


/* Return a random in range min to maxp1 - 1 */
void
_gbig_rand_range (BIGNUM *gbnr, BIGNUM *gbnmin, BIGNUM *gbnmaxp1)
{
	BIGNUM diff;

	BN_init(&diff);

	BN_sub (&diff, gbnmaxp1, gbnmin);
	BN_rand_range (gbnr, &diff);
	BN_add (gbnr, gbnr, gbnmin);
	BN_free (&diff);
}
