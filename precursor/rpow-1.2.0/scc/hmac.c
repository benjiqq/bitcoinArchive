/* HMAC function for IBM 4758 */

#include "gbignum.h"
#include "hmac.h"

void
gbig_hmac_buf (unsigned char *mac, void *key,
	unsigned long keylen, void *buf, unsigned long buflen)
{
	gbig_sha1ctx	ctx;
	unsigned char	keybuf[SHAINTERNALBYTES];
	unsigned char	keyxorbuf[SHAINTERNALBYTES];
	unsigned char	md[SHABYTES];
	int				i;

	if (keylen > SHAINTERNALBYTES)
	{
		gbig_sha1_buf (keybuf, key, keylen);
		memset (keybuf+SHABYTES, 0, SHAINTERNALBYTES-SHABYTES);
	}
	else
	{
		memcpy (keybuf, key, keylen);
		memset (keybuf+keylen, 0, SHAINTERNALBYTES-keylen);
	}

	gbig_sha1_init (&ctx);
	for (i=0; i<SHAINTERNALBYTES; i++)
		keyxorbuf[i] = keybuf[i] ^ 0x36;
	gbig_sha1_update (&ctx, keyxorbuf, SHAINTERNALBYTES);
	gbig_sha1_update (&ctx, buf, buflen);
	gbig_sha1_final (md, &ctx);

	gbig_sha1_init (&ctx);
	for (i=0; i<SHAINTERNALBYTES; i++)
		keyxorbuf[i] = keybuf[i] ^ 0x5c;
	gbig_sha1_update (&ctx, keyxorbuf, SHAINTERNALBYTES);
	gbig_sha1_update (&ctx, md, SHABYTES);
	gbig_sha1_final (mac, &ctx);
}

void
gbig_hmac_init(gbig_hmacctx *ctx, void *key, unsigned long keylen)
{
	unsigned char keyxorbuf[SHAINTERNALBYTES];
	int i;

	if (keylen > SHAINTERNALBYTES)
	{
		gbig_sha1_buf (ctx->key, key, keylen);
		memset (ctx->key+SHABYTES, 0, SHAINTERNALBYTES-SHABYTES);
	}
	else
	{
		memcpy (ctx->key, key, keylen);
		memset (ctx->key+keylen, 0, SHAINTERNALBYTES-keylen);
	}

	gbig_sha1_init (&ctx->sha1ctx);

	for (i=0; i<SHAINTERNALBYTES; i++)
		keyxorbuf[i] = ctx->key[i] ^ 0x36;
	gbig_sha1_update (&ctx->sha1ctx, keyxorbuf, SHAINTERNALBYTES);
}

void
gbig_hmac_update(gbig_hmacctx *ctx, void *buf, unsigned long len)
{
	gbig_sha1_update (&ctx->sha1ctx, buf, len);
}

void
gbig_hmac_final(unsigned char *mac, gbig_hmacctx *ctx)
{
	unsigned char	md[SHABYTES];
	unsigned char	keyxorbuf[SHAINTERNALBYTES];
	int				i;

	gbig_sha1_final (md, &ctx->sha1ctx);

	gbig_sha1_init (&ctx->sha1ctx);
	for (i=0; i<SHAINTERNALBYTES; i++)
		keyxorbuf[i] = ctx->key[i] ^ 0x5c;
	gbig_sha1_update (&ctx->sha1ctx, keyxorbuf, SHAINTERNALBYTES);
	gbig_sha1_update (&ctx->sha1ctx, md, SHABYTES);
	gbig_sha1_final (mac, &ctx->sha1ctx);
}
