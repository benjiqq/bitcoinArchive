/*
 * gbignum.c
 *	Generic bignum module implemented via IBM4758 hardware
 *	This runs on the IBM4758
 *	We use little-endian mode, it makes the math a little simpler
 */

#include <stdlib.h>
#include <string.h>
#include "gbignum.h"

#ifndef NULL
#define NULL	0
#endif /* NULL */

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif /* MIN */

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif /* MAX */

#define GBIG_EVEN(bn)  (((bn)->bytesize == 0) || (((bn)->buffer[0] & 1) == 0))

#define assert(x)


gbignum gbig_value_zero;
gbignum gbig_value_one;
gbignum gbig_value_two;
gbignum gbig_value_three;
static unsigned char _gbig_prime1024_buffer[128] = {
	0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static gbignum _gbig_value_prime1024 = {

	128, 1024, _gbig_prime1024_buffer
};
static unsigned char _gbig_prime2048_buffer[256] = {
	0xeb, 0xf9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static gbignum _gbig_value_prime2048 = {

	256, 2048, _gbig_prime2048_buffer
};


int
gbig_initialize ()
{
	gbig_from_word (&gbig_value_one, 1);
	gbig_from_word (&gbig_value_two, 2);
	gbig_from_word (&gbig_value_three, 3);
	return 0;
}

int
gbig_finalize ()
{
	gbig_free (&gbig_value_one);
	gbig_free (&gbig_value_two);
	gbig_free (&gbig_value_three);
	return 0;
}

/* Return zero on success, negative on failure */
int
gbig_rand_bytes (void *buf, unsigned len)
{
	unsigned char *ucbuf = buf;
	unsigned char buf8[8];
	unsigned len8;
	int err;

	while (len)
	{
		err = sccGetRandomNumber (buf8, RANDOM_HW|RANDOM_SW);
		assert (err == 0);
		len8 = MIN (len, 8);
		memcpy (ucbuf, buf8, len8);
		ucbuf += len8;
		len -= len8;
	}
	return 0;
}

/* Compute SHA1 of the specified buffer */
void
gbig_sha1_buf (unsigned char *md, void *buf, unsigned len)
{
	sccSHA_RB_t sha_rb;
	int err;

	memset (&sha_rb, 0, sizeof(sha_rb));
	sha_rb.options = SHA_INTERNAL_INPUT | SHA_MSGPART_ONLY;
	sha_rb.source.internal.count = len;
	sha_rb.source.internal.buffer = buf;
	if (len % 4 != 0)
		memcpy (sha_rb.final_data, (unsigned char *)buf+len-(len%4), len%4);
	err = sccSHA1 (&sha_rb);
	assert (err == 0);
	memcpy (md, sha_rb.hash_value, sizeof(sha_rb.hash_value));
}

void
gbig_sha1_init (gbig_sha1ctx *ctx)
{
	memset (ctx, 0, sizeof(gbig_sha1ctx));
}

/* For SHA, the engine can only update in mults of 64, so we buffer for it */
void
gbig_sha1_update (gbig_sha1ctx *ctx, void *buf, unsigned len)
{
	sccSHA_RB_t *sha_rb = &ctx->sha_rb;
	unsigned nlen;
	int err;

	if (ctx->buflen != 0)
	{
		nlen = MIN (len, sizeof(ctx->buf) - ctx->buflen);
		memcpy (ctx->buf+ctx->buflen, buf, nlen);
		buf = (unsigned char *)buf + nlen;
		ctx->buflen += nlen;
		len -= nlen;
		if (ctx->buflen == sizeof(ctx->buf))
		{
			if (sha_rb->running_length > 0)
				sha_rb->options = SHA_INTERNAL_INPUT | SHA_MSGPART_MIDDLE;
			else
				sha_rb->options = SHA_INTERNAL_INPUT | SHA_MSGPART_FIRST;
			sha_rb->source.internal.count = ctx->buflen;
			sha_rb->source.internal.buffer = ctx->buf;
			err = sccSHA1 (sha_rb);
			assert (err == 0);
			ctx->buflen = 0;
		}
	}
	nlen = len - (len % sizeof(ctx->buf));
	if (nlen != 0)
	{
		if (sha_rb->running_length > 0)
			sha_rb->options = SHA_INTERNAL_INPUT | SHA_MSGPART_MIDDLE;
		else
			sha_rb->options = SHA_INTERNAL_INPUT | SHA_MSGPART_FIRST;
		sha_rb->source.internal.count = nlen;
		sha_rb->source.internal.buffer = buf;
		err = sccSHA1 (sha_rb);
		assert (err == 0);
		len -= nlen;
		buf = (unsigned char *)buf + nlen;
	}

	if (len != 0)
	{
		memcpy (ctx->buf, buf, len);
		ctx->buflen = len;
	}
}

void
gbig_sha1_final (unsigned char *md, gbig_sha1ctx *ctx)
{
	sccSHA_RB_t *sha_rb = &ctx->sha_rb;
	unsigned len = ctx->buflen;
	int err;

	if (sha_rb->running_length > 0)
		sha_rb->options = SHA_INTERNAL_INPUT | SHA_MSGPART_FINAL;
	else
		sha_rb->options = SHA_INTERNAL_INPUT | SHA_MSGPART_ONLY;
	sha_rb->source.internal.count = len;
	sha_rb->source.internal.buffer = ctx->buf;
	if (len % 4 != 0)
		memcpy (sha_rb->final_data, ctx->buf+len-(len%4), len%4);
	err = sccSHA1 (sha_rb);
	assert (err == 0);
	memcpy (md, sha_rb->hash_value, sizeof(sha_rb->hash_value));
}

/* Set bytesize and bitsize properly */
void
_gbig_norm (gbignum *bna)
{
	int size = bna->bytesize;
	int bits;
	unsigned v;

	while (size > 0 && bna->buffer[size-1] == 0)
		--size;
	bna->bytesize = size;
	if (size == 0)
	{
		gbig_free (bna);
		return;
	}
	bits = 8*size - 7;
	v = bna->buffer[size-1];
	while (v >>= 1)
		++bits;
	bna->bitsize = bits;
}

/* Use the onboard math chip to do a mod, modmult, or modexp */
void
_gbig_modmath (int cmd, gbignum *bnc, gbignum *bnm, gbignum *bna, gbignum *bnb)
{
	int numbufs = (bnb==NULL) ? 3 : 4;
	gbignum bn[4];
	int err;

	bn[1] = *bnm;
	bn[2] = *bna;
	if (bnb)
		bn[3] = *bnb;

	/* Don't overwrite bnc yet in case it is a copy of one of the others */
	/* Getting a range overflow error, maybe the output buffer is too small */
	/* Yes, adding 2 fixed it (maybe adding 1 would have worked too) */
	bn[0].bytesize = bn[1].bytesize + 2;
	bn[0].buffer = malloc (bn[0].bytesize);

	err = sccModMath (cmd|MODM_LITTLE, numbufs, bn);
	if (err != 0)
	{
		/* Should not happen */
		/*printf ("sccModMath failed with code 0x%x\n", err)*/;
	}

	if (bnc->buffer != NULL)
		free (bnc->buffer);
	*bnc = bn[0];
	bnc->bytesize = (bnc->bitsize+7)/8;
}

void
gbig_init (gbignum *bn)
{
	memset (bn, 0, sizeof(*bn));
}

void
gbig_free (gbignum *bn)
{
	if (bn->buffer)
	{
		free (bn->buffer);
		bn->buffer = NULL;
	}
	bn->bytesize = bn->bitsize = 0;
}

void
gbig_copy (gbignum *bnb, gbignum *bna)
{
	if (bnb == bna)
		return;
	if (bnb->buffer)
		free (bnb->buffer);
	bnb->buffer = malloc (bna->bytesize);
	bnb->bytesize = bna->bytesize;
	bnb->bitsize = bna->bitsize;
	memcpy (bnb->buffer, bna->buffer, bna->bytesize);
}

void
gbig_add (gbignum *bnc, gbignum *bna, gbignum *bnb)
{
	unsigned sum, carry, i;
	unsigned char *buf;
	unsigned size;

	if (bna->bytesize < bnb->bytesize)
	{
		gbignum *tmp = bna; bna = bnb; bnb = tmp;
	}

	size = bna->bytesize + 1;
	buf = malloc (size);

	memcpy (buf, bna->buffer, bna->bytesize);
	buf[bna->bytesize] = 0;

	carry = 0;
	for (i=0; i<bnb->bytesize; ++i)
	{
		sum = buf[i] + bnb->buffer[i] + carry;
		carry = sum >> 8;
		buf[i] = sum;
	}
	for ( ; carry && i<size; ++i)
	{
		sum = buf[i] + carry;
		carry = sum >> 8;
		buf[i] = sum;
	}

	if (bnc->buffer)
		free (bnc->buffer);
	bnc->buffer = buf;
	bnc->bytesize = size;
	_gbig_norm (bnc);
}

void
gbig_sub (gbignum *bnc, gbignum *bna, gbignum *bnb)
{
	unsigned diff, borrow, i;
	unsigned char *buf;
	unsigned size;

	if (bna->bytesize < bnb->bytesize)
	{
		gbig_free (bnc);
		return;
	}

	size = bna->bytesize;
	buf = malloc (size);

	memcpy (buf, bna->buffer, bna->bytesize);

	borrow = 0;
	for (i=0; i<bnb->bytesize; ++i)
	{
		diff = buf[i] - bnb->buffer[i] - borrow;
		borrow = (diff >> 8) & 1;
		buf[i] = diff;
	}
	for ( ; borrow && i<size; ++i)
	{
		diff = buf[i] - borrow;
		borrow = (diff >> 8) & 1;
		buf[i] = diff;
	}

	if (bnc->buffer)
		free (bnc->buffer);
	bnc->buffer = buf;
	bnc->bytesize = size;
	_gbig_norm (bnc);
}

/* Mul by doing a mulmod with a big enough power of two! */
void
gbig_mul (gbignum *bnc, gbignum *bna, gbignum *bnb)
{
	gbignum bn;

	gbig_init (&bn);
	gbig_set_bit (&bn, bna->bitsize + bnb->bitsize);
	gbig_mod_mul (bnc, bna, bnb, &bn);
	gbig_free (&bn);
}

void
gbig_div (gbignum *bnc, gbignum *bna, gbignum *bnb)
{
	gbignum bn;

	gbig_init (&bn);
	gbig_div_mod (bnc, &bn, bna, bnb);
	gbig_free (&bn);
}

void
gbig_mod (gbignum *bnc, gbignum *bna, gbignum *bnb)
{
	_gbig_modmath (MODM_MOD, bnc, bnb, bna, NULL);
}

/* Crazy idea to try multiplying by the inverse mod a large prime */
void
gbig_div_mod (gbignum *bnq, gbignum *bnr, gbignum *bna, gbignum *bnb)
{
	gbignum *p;
	gbignum bnpm2, bnbinv;
	gbignum bnqq, bnrr;

	gbig_init (&bnpm2);
	gbig_init (&bnbinv);
	gbig_init (&bnqq);
	gbig_init (&bnrr);
	if (bna->bitsize - bnb->bitsize < 1023)
		p = &_gbig_value_prime1024;
	else
		p = &_gbig_value_prime2048;
	gbig_mod (&bnrr, bna, bnb);
	gbig_sub (&bnqq, bna, &bnrr);
	gbig_sub (&bnpm2, p, &gbig_value_two);
	gbig_mod_exp (&bnbinv, bnb, &bnpm2, p);
	gbig_mod_mul (&bnqq, &bnqq, &bnbinv, p);
	gbig_copy (bnq, &bnqq);
	gbig_copy (bnr, &bnrr);
	gbig_free (&bnpm2);
	gbig_free (&bnbinv);
	gbig_free (&bnqq);
	gbig_free (&bnrr);
}

void
gbig_mod_add (gbignum *bnc, gbignum *bna, gbignum *bnb, gbignum *bnm)
{
	gbignum bncc;

	gbig_init (&bncc);
	gbig_add (&bncc, bna, bnb);
	gbig_mod (&bncc, &bncc, bnm);
	gbig_copy (bnc, &bncc);
	gbig_free (&bncc);
}

void
gbig_mod_sub (gbignum *bnc, gbignum *bna, gbignum *bnb, gbignum *bnm)
{
	gbignum bncc;

	gbig_init (&bncc);
	gbig_copy (&bncc, bna);
	while (gbig_cmp (&bncc, bnb) < 0)
		gbig_add (&bncc, &bncc, bnm);
	gbig_sub (&bncc, &bncc, bnb);
	gbig_mod (&bncc, &bncc, bnm);
	gbig_copy (bnc, &bncc);
	gbig_free (&bncc);
}

void
gbig_mod_mul (gbignum *bnc, gbignum *bna, gbignum *bnb, gbignum *bnm)
{
	_gbig_modmath (MODM_MULT, bnc, bnm, bna, bnb);
}

void
gbig_mod_exp (gbignum *bnc, gbignum *bna, gbignum *bnb, gbignum *bnm)
{
	_gbig_modmath (MODM_EXP, bnc, bnm, bna, bnb);
}


/* Algorithm X from Knuth */
void
gbig_mod_inverse (gbignum *bnb, gbignum *bna, gbignum *bnm)
{
	gbignum u2, u3;
	gbignum v2, v3;
	gbignum t2, t3;
	gbignum q;
	int u2sign = 1;
	int v2sign = 1;
	int tmp;

	gbig_init (&u2);
	gbig_init (&u3);
	gbig_init (&v2);
	gbig_init (&v3);
	gbig_init (&t2);
	gbig_init (&t3);
	gbig_init (&q);

	gbig_copy (&v3, bna);
	gbig_copy (&u3, bnm);
	gbig_from_word (&v2, 1);

	while (v3.bytesize > 0)
	{
		gbig_div_mod (&q, &t3, &u3, &v3);
		gbig_mul (&t2, &v2, &q);
		if (u2sign != v2sign)
			gbig_add (&t2, &u2, &t2);
		else {
			if (gbig_cmp (&u2, &t2) > 0)
			{
				gbig_sub (&t2, &u2, &t2);
			} else {
				gbig_sub (&t2, &t2, &u2);
				u2sign = -u2sign;
			}
		}
		gbig_copy (&u2, &v2);
		gbig_copy (&u3, &v3);
		gbig_copy (&v2, &t2);
		gbig_copy (&v3, &t3);
		tmp = u2sign; u2sign=v2sign; v2sign=tmp;
	}

	if (u2sign == 1)
		gbig_copy (bnb, &u2);
	else
		gbig_sub (bnb, bnm, &u2);
	gbig_free (&u2);
	gbig_free (&u3);
	gbig_free (&v2);
	gbig_free (&v3);
	gbig_free (&t2);
	gbig_free (&t3);
	gbig_free (&q);
}


int
gbig_cmp (gbignum *bna, gbignum *bnb)
{
	unsigned size = MAX (bna->bytesize, bnb->bytesize);
	unsigned a, b;
	unsigned i;

	for (i=0; i<size; i++)
	{
		a = (i >= size - bna->bytesize) ? bna->buffer[size-1-i] : 0;
		b = (i >= size - bnb->bytesize) ? bnb->buffer[size-1-i] : 0;
		if (a > b)
			return 1;
		else if (a < b)
			return -1;
	}
	return 0;
}

void
gbig_from_word (gbignum *bna, unsigned n)
{
	if (n == 0)
	{
		gbig_free (bna);
		return;
	}
	if (bna->buffer)
		free (bna->buffer);
	bna->bytesize = 4;
	bna->buffer = malloc (4);
	bna->buffer[3] = n >> 24;
	bna->buffer[2] = n >> 16;
	bna->buffer[1] = n >> 8;
	bna->buffer[0] = n;
	_gbig_norm (bna);
}

unsigned
gbig_to_word (gbignum *bna)
{
	unsigned v = 0;
	int i = MIN (4, bna->bytesize);

	while (--i >= 0)
		v = (v << 8) | bna->buffer[i];
	return v;
}

static void
_gbig_set_clear_bit (gbignum *bna, unsigned n, int set)
{
	unsigned len = n/8 + 1;
	int bit = 1 << (n & 7);
	if (bna->bytesize < len)
	{
		if (!set)
			return;
		if (bna->buffer == NULL)
			bna->buffer = malloc (len);
		else
			bna->buffer = realloc (bna->buffer, len);
		memset (bna->buffer + bna->bytesize, 0, len - bna->bytesize);
		bna->bytesize = len;
	}
	if (set)
		bna->buffer[len-1] |= bit;
	else
		bna->buffer[len-1] &= ~bit;
	_gbig_norm (bna);
}

void
gbig_set_bit (gbignum *bna, unsigned n)
{
	_gbig_set_clear_bit (bna, n, 1);
}

void
gbig_clear_bit (gbignum *bna, unsigned n)
{
	_gbig_set_clear_bit (bna, n, 0);
}

void
gbig_to_buf (void *buf, gbignum *bna)
{
	unsigned i;
	unsigned char *ucbuf = buf;

	for (i=0; i<bna->bytesize; i++)
		ucbuf[i] = bna->buffer[bna->bytesize-1-i];
}

void
gbig_to_buf_len (void *buf, unsigned len, gbignum *bna)
{
	if (len < bna->bytesize)
		return;
	if (len > bna->bytesize)
		memset (buf, 0, len - bna->bytesize);
	gbig_to_buf ((unsigned char *)buf+len-bna->bytesize, bna);
}

unsigned
gbig_buflen (gbignum *bna)
{
	return bna->bytesize;
}

void
gbig_from_buf (gbignum *bna, void *buf, int buflen)
{
	unsigned char *ucbuf = buf;
	int i;

	if (bna->buffer)
		free (bna->buffer);
	bna->bytesize = buflen;
	bna->buffer = malloc (buflen);
	for (i=0; i<buflen; i++)
		bna->buffer[i] = ucbuf[buflen-1-i];
	_gbig_norm (bna);
}


void
gbig_rand_range (gbignum *bnr, gbignum *bna, gbignum *bnb)
{
	gbignum bn1, bn2;
	int mask;

	gbig_init (&bn1);
	gbig_init (&bn2);

	gbig_sub (&bn1, bnb, bna);

	if (bn1.bytesize==0 || (bn1.bytesize==1 && bn1.buffer[0] == 1))
	{
		gbig_free (bnr);
		return;
	}

	bn2.bytesize = bn1.bytesize;
	bn2.buffer = malloc (bn2.bytesize);

	mask = (1 << (((bn1.bitsize-1)%8)+1)) - 1;

	do {
		gbig_rand_bytes (bn2.buffer, bn2.bytesize);
		bn2.buffer[bn2.bytesize-1] &= mask;
	} while (gbig_cmp (&bn2, &bn1) >= 0);

	_gbig_norm (&bn2);

	gbig_add (bnr, &bn2, bna);

	gbig_free (&bn1);
	gbig_free (&bn2);

}
