/*
 * cryptchan.c
 * Client side of a secure encrypted channel to the 4758.
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
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "scc.h"

#include "util4758.h"
#include "cryptchan.h"

/* Size of our master secret, matches HMAC input */
#define SHAINTERNALBYTES	64


/*
 * Given an RSA key, create a random master secret, encrypt it using
 * the key, and put it in the output.  Also generate our TDES
 * I/O keys and associated values and return those in encdata.
 */
int
encryptmaster (struct encstate *encdata, RSA *rsa,
	unsigned char **outbuf, unsigned long *outbuflen)
{
	unsigned char		masterkeybuf[SHAINTERNALBYTES];
	unsigned char		mac[SHABYTES];
	static unsigned char	enckeybuf[RSAKEYBYTES];

	if (RSA_size(rsa) != sizeof(enckeybuf))
	{
		fprintf (stderr, "Key size %d not expected\n", RSA_size(rsa));
		return -1;
	}

	RAND_bytes (masterkeybuf, sizeof(masterkeybuf));

	if (RSA_public_encrypt (sizeof(masterkeybuf), masterkeybuf, enckeybuf, rsa,
			RSA_PKCS1_OAEP_PADDING) < 0)
	{
		fprintf (stderr, "RSA encryption failed\n");
		return -1;
	}

	*outbuf = enckeybuf;
	*outbuflen = sizeof(enckeybuf);

	/* Generate the shared keys */
	memset (encdata, 0, sizeof(*encdata));
	HMAC (EVP_sha1(), masterkeybuf, sizeof(masterkeybuf), "EKI1", 4, mac, NULL);
	memcpy (encdata->tdeskeyin, mac, SHABYTES);
	HMAC (EVP_sha1(), masterkeybuf, sizeof(masterkeybuf), "EKI2", 4, mac, NULL);
	memcpy (encdata->tdeskeyin+SHABYTES, mac, TDESKEYBYTES-SHABYTES);
	HMAC (EVP_sha1(), masterkeybuf, sizeof(masterkeybuf), "EKO1", 4, mac, NULL);
	memcpy (encdata->tdeskeyout, mac, SHABYTES);
	HMAC (EVP_sha1(), masterkeybuf, sizeof(masterkeybuf), "EKO2", 4, mac, NULL);
	memcpy (encdata->tdeskeyout+SHABYTES, mac, TDESKEYBYTES-SHABYTES);
	HMAC (EVP_sha1(), masterkeybuf, sizeof(masterkeybuf), "MKI1", 4, encdata->hmackeyin, NULL);
	HMAC (EVP_sha1(), masterkeybuf, sizeof(masterkeybuf), "MKO1", 4, encdata->hmackeyout, NULL);

	return 0;
}


/* Increment a seqno */
static void
incrementseqno (unsigned char *seqno)
{
	int i;
	for (i=SEQNOBYTES-1; i>=0; i--)
		if (++seqno[i])
			break;
}


/* Do a TDES decrypt for coming from the card.  This also unpads. */
int
tdesdecrypt (unsigned char *obuf, unsigned long *outlen,
	struct encstate *encdata, unsigned char *ibuf, unsigned long buflen)
{
	EVP_CIPHER_CTX	ctx;
	int				outl;

	EVP_CIPHER_CTX_init (&ctx);
	EVP_DecryptInit_ex (&ctx, EVP_des_ede3_cbc(), NULL, encdata->tdeskeyin,
		ibuf);
	EVP_DecryptUpdate (&ctx, obuf, &outl, ibuf+TDESBYTES, buflen-TDESBYTES);
	*outlen = outl;
	if (EVP_DecryptFinal_ex (&ctx, obuf+outl, &outl) == 0)
	{
		fprintf (stderr, "Bad format on decrypted data from card\n");
		return -1;
	}
	EVP_CIPHER_CTX_cleanup (&ctx);
	*outlen += outl;
	return 0;
}


/* Do a TDES encrypt for going to the card.  This also pads, so the output
 * buffer should be 8 bytes bigger than the input buffer.
 */
int
tdesencrypt (unsigned char *obuf, unsigned long *outlen,
	struct encstate *encdata, unsigned char *ibuf, unsigned long buflen)
{
	EVP_CIPHER_CTX	ctx;
	unsigned char	iv[TDESBYTES];
	int				outl;

	RAND_bytes (iv, TDESBYTES);
	memcpy (obuf, iv, TDESBYTES);
	EVP_CIPHER_CTX_init (&ctx);
	EVP_EncryptInit_ex (&ctx, EVP_des_ede3_cbc(), NULL, encdata->tdeskeyout,
		iv);
	EVP_EncryptUpdate (&ctx, obuf+TDESBYTES, &outl, ibuf, buflen);
	*outlen = outl + TDESBYTES;
	if (EVP_EncryptFinal_ex (&ctx, obuf+TDESBYTES+outl, &outl) == 0)
	{
		fprintf (stderr, "Internal error encrypting data for card\n");
		return -1;
	}
	EVP_CIPHER_CTX_cleanup (&ctx);
	*outlen += outl;
	return 0;
}

/* TDES encrypt the buffer and put in the output */
int
encryptoutput (struct encstate *encdata, unsigned char *buf,
	unsigned long buflen, unsigned char **outbuf, unsigned long *outbuflen)
{
	long			rc;
	HMAC_CTX		hmac;
	unsigned char	*encbuf;
	unsigned long	encbuflen;

	encbuf = malloc (buflen + 2*TDESBYTES + SHABYTES);
	if ((rc = tdesencrypt (encbuf, &encbuflen, encdata, buf, buflen)) < 0)
		return rc;

	HMAC_CTX_init (&hmac);
	HMAC_Init_ex (&hmac, encdata->hmackeyout, sizeof(encdata->hmackeyout),
					EVP_sha1(), NULL);
	HMAC_Update (&hmac, encdata->seqnoout, sizeof(encdata->seqnoout));
	HMAC_Update (&hmac, encbuf, encbuflen);
	HMAC_Final (&hmac, encbuf+encbuflen, NULL);
	HMAC_CTX_cleanup (&hmac);

	encbuflen += SHABYTES;

	incrementseqno (encdata->seqnoout);

	*outbuf = encbuf;
	*outbuflen = encbuflen;
	return 0;
}



/* TDES decrypt input buffer, return in *buf and *buflen */
int
decryptinput (unsigned char **buf, unsigned long *buflen,
	struct encstate *encdata, unsigned char *inbuf, unsigned long inbuflen)
{
	long			rc;
	HMAC_CTX		hmac;
	unsigned char	*clrbuf;
	unsigned long	clrbuflen;
	unsigned char	mac[SHABYTES];

	*buf = NULL;
	*buflen = 0;

	HMAC_CTX_init (&hmac);
	HMAC_Init_ex (&hmac, encdata->hmackeyin, sizeof(encdata->hmackeyin),
					EVP_sha1(), NULL);
	HMAC_Update (&hmac, encdata->seqnoin, sizeof(encdata->seqnoin));
	HMAC_Update (&hmac, inbuf, inbuflen-SHABYTES);
	HMAC_Final (&hmac, mac, NULL);
	HMAC_CTX_cleanup (&hmac);

	if (memcmp (mac, inbuf+inbuflen-SHABYTES, SHABYTES) != 0)
	{
		fprintf (stderr, "Invalid MAC on message from card\n");
		return -1;
	}

	inbuflen -= SHABYTES;

	clrbuf = malloc (inbuflen);
	if ((rc = tdesdecrypt (clrbuf, &clrbuflen, encdata, inbuf, inbuflen)) < 0)
		return rc;

	incrementseqno (encdata->seqnoin);

	*buf = clrbuf;
	*buflen = clrbuflen;
	return 0;
}
