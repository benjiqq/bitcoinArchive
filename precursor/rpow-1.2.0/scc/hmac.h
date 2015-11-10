/* hmac.h */
#ifndef SHA1_H
#define SHA1_H

#include <stdlib.h>
#include <string.h>
#include <scctypes.h>
#include <scc_int.h>
#include "gbignum.h"
#include "errors.h"

#define SHABYTES				20
#define SHAINTERNALBYTES		64

typedef struct gbig_hmacctx {
	gbig_sha1ctx	sha1ctx;
	unsigned char	key[SHAINTERNALBYTES];
} gbig_hmacctx;


void gbig_hmac_buf (unsigned char *mac, void *key,
	unsigned long keylen, void *buf, unsigned long buflen);
void gbig_hmac_init(gbig_hmacctx *ctx, void *key, unsigned long keylen);
void gbig_hmac_update(gbig_hmacctx *ctx, void *buf, unsigned long len);
void gbig_hmac_final(unsigned char *mac, gbig_hmacctx *ctx);

#endif
