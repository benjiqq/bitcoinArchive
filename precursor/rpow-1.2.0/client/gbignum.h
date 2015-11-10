/*
 * gbignum.h
 * Generic bignum module, wrapper around OpenSSL library.
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

#ifndef GBIGNUM_H
#define GBIGNUM_H

#include <openssl/bn.h>
#include <openssl/sha.h>

extern BN_CTX	*bnctx;
typedef BIGNUM	gbignum;
typedef SHA_CTX	gbig_sha1ctx;

#ifndef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH	20
#endif /* SHA1_DIGEST_LENGTH */

extern int gbig_initialize(void);
extern int gbig_finalize(void);
extern int gbig_rand_bytes(void *,unsigned);
extern void _gbig_rand_range (BIGNUM *, BIGNUM *, BIGNUM *);
extern gbignum gbig_value_zero;
extern gbignum gbig_value_one;
extern gbignum gbig_value_two;
extern gbignum gbig_value_three;

#define gbig_sha1_buf(md,buf,len) \
							SHA1 (buf,len,md)
#define gbig_sha1_init(ctx) \
							SHA1_Init (ctx)
#define gbig_sha1_update(ctx,buf,len) \
							SHA1_Update (ctx, buf, len)
#define gbig_sha1_final(md,ctx) \
							SHA1_Final (md, ctx)

#define gbig_init(gbna)		BN_init(gbna)
#define gbig_free(gbna)		BN_free(gbna)
#define gbig_copy(gbnb,gbna) \
							BN_copy(gbnb, gbna)
#define gbig_add(gbnc,gbna,gbnb) \
							BN_add(gbnc,gbna,gbnb)
#define gbig_sub(gbnc,gbna,gbnb) \
							BN_sub(gbnc,gbna,gbnb)
#define gbig_mul(gbnc,gbna,gbnb) \
							BN_mul(gbnc,gbna,gbnb,bnctx)
#define gbig_div(gbnc,gbna,gbnb) \
							BN_div(gbnc,NULL,gbna,gbnb,bnctx)
#define gbig_mod(gbnc,gbna,gbnb) \
							BN_mod(gbnc,gbna,gbnb,bnctx)
#define gbig_div_mod(gbnd,gbnr,gbna,gbnb) \
							BN_div(gbnd,gbnr,gbna,gbnb,bnctx)
#define gbig_mod_add(gbnc,gbna,gbnb,gbnm) \
							BN_mod_add(gbnc,gbna,gbnb,gbnm,bnctx)
#define gbig_mod_sub(gbnc,gbna,gbnb,gbnm) \
							BN_mod_sub(gbnc,gbna,gbnb,gbnm,bnctx)
#define gbig_mod_mul(gbnc,gbna,gbnb,gbnm) \
							BN_mod_mul(gbnc,gbna,gbnb,gbnm,bnctx)
#define gbig_mod_exp(gbnc,gbna,gbnb,gbnm) \
							BN_mod_exp(gbnc,gbna,gbnb,gbnm,bnctx)
#define gbig_mod_inverse(gbnc,gbna,gbnm) \
							BN_mod_inverse(gbnc,gbna,gbnm,bnctx)
#define gbig_gcd(gbnc,gbna,gbnb) \
							BN_gcd(gbnc,gbna,gbnb,bnctx)

#define gbig_cmp(gbna,gbnb) \
							BN_cmp(gbna,gbnb)
#define gbig_from_word(gbna,n) \
							BN_set_word(gbna,(n))
#define gbig_to_word(gbna) \
							BN_get_word(gbna)
#define gbig_set_bit(gbna,bit) \
							BN_set_bit(gbna,bit)
#define gbig_clear_bit(gbna,bit) \
							BN_clear_bit(gbna,bit)
#define gbig_shift_left(gbnb,gbna,bit) \
							BN_lshift(gbnb,gbna,bit)
#define gbig_shift_right(gbnb,gbna,bit) \
							BN_rshift(gbnb,gbna,bit)

#define gbig_to_buf(buf,gbna) \
							BN_bn2bin(gbna,buf)
#define gbig_from_buf(gbna,buf,buflen) \
							BN_bin2bn(buf,buflen,gbna)
#define gbig_buflen(gbna) \
							BN_num_bytes(gbna)

#define gbig_rand_range(gbnr,gbna,gbnb) \
							_gbig_rand_range(gbnr,gbna,gbnb)
#define gbig_is_prime(gbna) \
							BN_is_prime(gbna,0,NULL,bnctx,NULL)
#define gbig_generate_prime(gbnr,bits) \
							BN_generate_prime (gbnr,bits,0,NULL,NULL,NULL,NULL)




#endif /* GBIGNUM_H */
