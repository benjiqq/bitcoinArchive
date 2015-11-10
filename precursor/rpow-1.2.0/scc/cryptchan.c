/* Set up a secure crypto channel from/to the host */

#include "cryptchan.h"


static int setkeys (struct encstate *encdata, unsigned char *clrkeybuf,
		unsigned long clrkeybuflen);

/* Return a key in a malloc buffer */
int
keyfromcert (sccRSAKeyToken_t **pkey, unsigned long *pkeylen,
	sccOA_CKO_Name_t *certname)
{
	long				rc;
	unsigned char		*certbuf;
	unsigned long		certlen;
	sccOA_CKO_Head_t	*head;
	sccOA_CKO_Body_t	*body;
	sccRSAKeyToken_t	*key;

	if ((rc = sccOAGetCert (certname, NULL, &certlen)) != 0)
		return ERR_FAILEDOA;
	if ((certbuf = malloc (certlen)) == 0)
		return ERR_NOMEM;
	if ((rc = sccOAGetCert (certname, certbuf, &certlen)) != 0)
		return ERR_FAILEDOA;
	head = (sccOA_CKO_Head_t *)certbuf;
	body = (sccOA_CKO_Body_t *)(((unsigned char *)&head->vData) + head->vData.offset);
	key = (sccRSAKeyToken_t *)(((unsigned char *)&body->vPublic) + body->vPublic.offset);
	*pkeylen = body->vPublic.len;
	if ((*pkey = malloc (*pkeylen)) == NULL)
		return ERR_NOMEM;
	memcpy (*pkey, key, *pkeylen);
	free (certbuf);
	return 0;
}

/*
 * OAEP helper function, hash input to specified output length
 */
static void
MGF1 (unsigned char *to, unsigned tlen, unsigned char *from, unsigned flen)
{
	unsigned long ncnt;
	unsigned outlen = 0;
	gbig_sha1ctx sha1;
	unsigned char md[SHA1_DIGEST_LENGTH];
	int i;

	for (i=0; outlen < tlen; i++)
	{
		gbig_sha1_init (&sha1);
		gbig_sha1_update (&sha1, from, flen);
		ncnt = rswapl (i);
		gbig_sha1_update (&sha1, &ncnt, sizeof(ncnt));
		if (outlen + SHA1_DIGEST_LENGTH <= tlen)
		{
			gbig_sha1_final (to + outlen, &sha1);
			outlen += SHA1_DIGEST_LENGTH;
		} else {
			gbig_sha1_final (md, &sha1);
			memcpy (to + outlen, md, tlen-outlen);
			outlen = tlen;
		}
	}
}

/*
 * Do a PKCS-1 V2 OAEP unpad, using SHA-1, MGF1 and empty param.
 * Assume input is full length of the modulus.
 */
static int
oaep_unpad (unsigned char *to, unsigned tlen,
	unsigned char *from, unsigned flen)
{
	unsigned char *maskeddb;
	unsigned dblen;
	unsigned char db[MAXRSAKEYBYTES];
	unsigned char seed[SHA1_DIGEST_LENGTH];
	static unsigned char emptyhash[SHA1_DIGEST_LENGTH] = {
		0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
		0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
		0xaf, 0xd8, 0x07, 0x09
	};
	unsigned i;
	int rc = 0;		/* return code */

	/* OAEP unpadding */
	if (from[0] != 0)
		rc = -1;
	maskeddb = from + 1 + SHA1_DIGEST_LENGTH;
	dblen = flen - 1 - SHA1_DIGEST_LENGTH;
	MGF1 (seed, SHA1_DIGEST_LENGTH, maskeddb, dblen);
	for (i=0; i<SHA1_DIGEST_LENGTH; i++)
		seed[i] ^= from[i+1];
	MGF1 (db, dblen, seed, SHA1_DIGEST_LENGTH);
	for (i=0; i<dblen; i++)
		db[i] ^= maskeddb[i];
	if (memcmp (db, emptyhash, SHA1_DIGEST_LENGTH) != 0)
		rc = -1;
	for (i=SHA1_DIGEST_LENGTH; i<dblen; i++)
		if (db[i] != 0)
			break;
	if (db[i] != 1 || i == dblen)
		rc = -1;
	if (tlen != (dblen - ++i))
		rc = -1;
	memcpy (to, db+i, tlen);
	return rc;
}



/* Decrypt encrypted master secret, setting up encstate for later work */
/* We ignore padding errors but set a failed flag */
/* This entry point takes an RSA private key */
int
decryptmaster (struct encstate *encdata, sccRequestHeader_t *req,
		sccRSAKeyToken_t *key, unsigned long keylen, int bufidx)
{
	long				rc;
	unsigned char		enckeybuf[MAXRSAKEYBYTES];
	unsigned char		clrkeybuf[MAXRSAKEYBYTES];
	sccRSA_RB_t			rsarb;

	if ((rc = sccGetBufferData (req->RequestID, bufidx, enckeybuf,
			key->n_Length)) < 0)
		return ERR_FAILEDGETBUFFER;

	/* Set up for decryption.  */
	memset (&rsarb, 0, sizeof(rsarb));
	rsarb.options = RSA_PRIVATE | RSA_DECRYPT | RSA_BLIND_NO_UPDATE;
	rsarb.data_in = enckeybuf;
	rsarb.data_out = clrkeybuf;
	rsarb.data_size = key->n_BitLength;;
	rsarb.key_token = key;
	rsarb.key_size = keylen;
	if ((rc = sccRSA (&rsarb)) != 0)
		return ERR_FAILEDRSADECRYPT;

	if ((rc = setkeys (encdata, clrkeybuf, key->n_Length)) != 0)
		return rc;

	return 0;
}

/* Given our decrypted buffer, extract master secret and set up keys */
static int
setkeys (struct encstate *encdata, unsigned char *clrkeybuf,
	unsigned long clrkeybuflen)
{
	unsigned char		masterkeybuf[SHAINTERNALBYTES];
	unsigned char		mac[SHABYTES];

	memset (encdata, 0, sizeof(struct encstate));

	if (oaep_unpad (masterkeybuf, sizeof(masterkeybuf),
				clrkeybuf, clrkeybuflen) != 0)
		encdata->failed = 1;

	/* Generate the four keys */
	gbig_hmac_buf (mac, masterkeybuf, sizeof(masterkeybuf), "EKI1", 4);
	memcpy (encdata->tdeskeyin, mac, SHABYTES);
	gbig_hmac_buf (mac, masterkeybuf, sizeof(masterkeybuf), "EKI2", 4);
	memcpy (encdata->tdeskeyin+SHABYTES, mac, TDESKEYBYTES-SHABYTES);
	gbig_hmac_buf (mac, masterkeybuf, sizeof(masterkeybuf), "EKO1", 4);
	memcpy (encdata->tdeskeyout, mac, SHABYTES);
	gbig_hmac_buf (mac, masterkeybuf, sizeof(masterkeybuf), "EKO2", 4);
	memcpy (encdata->tdeskeyout+SHABYTES, mac, TDESKEYBYTES-SHABYTES);
	gbig_hmac_buf (mac, masterkeybuf, sizeof(masterkeybuf), "IVI1", 4);
	gbig_hmac_buf (encdata->hmackeyin, masterkeybuf, sizeof(masterkeybuf), "MKI1", 4);
	gbig_hmac_buf (encdata->hmackeyout, masterkeybuf, sizeof(masterkeybuf), "MKO1", 4);

	return 0;
}

/* Increment sequence number */
static void
incrementseqno (unsigned char *seqno)
{
	int i;
	for (i=SEQNOBYTES-1; i>=0; i--)
		if (++seqno[i])
			break;
}


/* Pad and unpad buffers for TDES */
/* Padding outputs to a malloc buffer */
/* Note that we write to every byte of the buffer so we don't leak data */
int
tdespad (unsigned char **obuf, unsigned long *obuflen, unsigned char *ibuf,
	unsigned long ibuflen)
{
	int padding = TDESBYTES - (ibuflen % TDESBYTES);
	*obuf = malloc (ibuflen + padding);
	if (*obuf == NULL)
		return ERR_NOMEM;
	memcpy (*obuf, ibuf, ibuflen);
	memset ((*obuf)+ibuflen, padding, padding);
	*obuflen = ibuflen + padding;
	return 0;
}

/* Unpadding remains in the same buffer */
int
tdesunpad (unsigned long *obuflen, unsigned char *buf, unsigned long buflen)
{
	unsigned padding = buf[buflen-1];
	if (padding > TDESBYTES || padding > buflen)
		return ERR_INVALID;
	*obuflen = buflen - padding;
	return 0;
}


/* Do a TDES encrypt for going to the host.  obuf will get the IV so
 * must be buflen+TDESBYTES long
 */
int
tdesencrypt (unsigned char *obuf, unsigned char *key, unsigned char *ibuf,
	unsigned long buflen)
{
	long				rc;
	sccTDES_RB_t		tdesrb;

	if (buflen % TDESBYTES)
		return ERR_INVALID;

	/* Put IV into the beginning of the output buffer */
	sccGetRandomNumber (obuf, RANDOM_RANDOM | RANDOM_HW | RANDOM_SW);

	/* Encrypt the data (note that "in" is host relative */
	memset (&tdesrb, 0, sizeof(tdesrb));
	tdesrb.options = DES_ENCRYPT | DES_TRIPLE_DES | DES_USE_KEY | DES_CBC_MODE
			| DES_INTERNAL_INPUT | DES_INTERNAL_OUTPUT; 
	memcpy (tdesrb.key1, key, TDESKEYBYTES/3);
	memcpy (tdesrb.key2, key + TDESKEYBYTES/3, TDESKEYBYTES/3);
	memcpy (tdesrb.key3, key + 2*TDESKEYBYTES/3, TDESKEYBYTES/3);
	memcpy (tdesrb.init_v, obuf, TDESBYTES);
	tdesrb.source.internal.buffer = ibuf;
	tdesrb.source.internal.count = buflen;
	tdesrb.destination.internal.buffer = obuf+TDESBYTES;
	tdesrb.destination.internal.count = buflen;

	if ((rc = sccTDES (&tdesrb)) != 0)
		return ERR_FAILEDTDESENCRYPT;

	return 0;
}

/* Do a TDES decrypt for coming from the host */
/* buflen counts the iv, so obuf is TDESBYTES shorter than buflen */
int
tdesdecrypt (unsigned char *obuf, unsigned char *key, unsigned char *ibuf,
	unsigned long buflen)
{
	long				rc;
	sccTDES_RB_t		tdesrb;

	if (buflen % TDESBYTES)
		return ERR_INVALID;

	/* Decrypt the data (note that "out" is host relative */
	memset (&tdesrb, 0, sizeof(tdesrb));
	tdesrb.options = DES_DECRYPT | DES_TRIPLE_DES | DES_USE_KEY | DES_CBC_MODE
			| DES_INTERNAL_INPUT | DES_INTERNAL_OUTPUT; 
	memcpy (tdesrb.key1, key, TDESKEYBYTES/3);
	memcpy (tdesrb.key2, key + TDESKEYBYTES/3, TDESKEYBYTES/3);
	memcpy (tdesrb.key3, key + 2*TDESKEYBYTES/3, TDESKEYBYTES/3);
	memcpy (tdesrb.init_v, ibuf, TDESBYTES);
	tdesrb.source.internal.buffer = ibuf+TDESBYTES;
	tdesrb.source.internal.count = buflen-TDESBYTES;
	tdesrb.destination.internal.buffer = obuf;
	tdesrb.destination.internal.count = buflen-TDESBYTES;

	if ((rc = sccTDES (&tdesrb)) != 0)
		return ERR_FAILEDTDESDECRYPT;

	return 0;
}

/* TDES decrypt the input buffer, return in *buf and *buflen */
int
decryptinput (unsigned char **buf, unsigned long *buflen,
	struct encstate *encdata, sccRequestHeader_t *req, int bufidx)
{
	long			rc;
	gbig_hmacctx	hmac;
	unsigned long	encbuflen;
	unsigned char	*encbuf;
	unsigned char	*clrbuf;
	unsigned char	mac[SHABYTES];

	*buf = NULL;
	*buflen = 0;

	if (encdata->failed)
		return ERR_INVALID;

	encbuflen = req->OutBufferLength[bufidx];
	if (encbuflen > MAXINPUTLEN)
		return ERR_BADINPUT;

	encbuf = malloc (encbuflen);
	if (encbuf == NULL)
		return ERR_NOMEM;

	if ((rc = sccGetBufferData (req->RequestID, bufidx,
				encbuf, encbuflen)) < 0)
		return ERR_FAILEDGETBUFFER;

	gbig_hmac_init (&hmac, encdata->hmackeyout, sizeof(encdata->hmackeyout));
	gbig_hmac_update (&hmac, encdata->seqnoout, SEQNOBYTES);
	gbig_hmac_update (&hmac, encbuf, encbuflen-SHABYTES);
	gbig_hmac_final (mac, &hmac);
	if (memcmp (mac, encbuf+encbuflen-SHABYTES, SHABYTES) != 0)
	{
		free (encbuf);
		return ERR_INVALID;
	}
	encbuflen -= SHABYTES;

	if (encbuflen % TDESBYTES)
		return ERR_INVALID;

	clrbuf = malloc (encbuflen);
	if (clrbuf == NULL)
		return ERR_NOMEM;

	if ((rc = tdesdecrypt (clrbuf, encdata->tdeskeyout, encbuf, encbuflen)) < 0)
		return rc;

	if ((rc = tdesunpad (buflen, clrbuf, encbuflen-TDESBYTES)) < 0)
		return rc;

	incrementseqno (encdata->seqnoout);

	*buf = clrbuf;
	free (encbuf);
	return 0;
}


/* TDES encrypt the buffer and send to the host */
/* Note that we write to every byte of the output buffer */
int
encryptoutput (struct encstate *encdata, unsigned char *buf, unsigned long buflen,
	sccRequestHeader_t *req, int bufidx)
{
	long			rc;
	gbig_hmacctx	hmac;
	unsigned long	encbuflen;
	unsigned char	*encbuf;
	unsigned char	*clrbuf;

	if (encdata->failed)
		return ERR_INVALID;

	if (buflen > req->InBufferLength[bufidx])
		return ERR_INVALID;

	if ((rc = tdespad (&clrbuf, &encbuflen, buf, buflen)) < 0)
		return rc;

	encbuf = malloc (TDESBYTES + encbuflen + SHABYTES);
	if (encbuf == NULL)
		return ERR_NOMEM;

	if ((rc = tdesencrypt (encbuf, encdata->tdeskeyin, clrbuf, encbuflen)) < 0)
		return rc;
	encbuflen += TDESBYTES;		/* IV */

	gbig_hmac_init (&hmac, encdata->hmackeyin, sizeof(encdata->hmackeyin));
	gbig_hmac_update (&hmac, encdata->seqnoin, SEQNOBYTES);
	gbig_hmac_update (&hmac, encbuf, encbuflen);
	gbig_hmac_final (encbuf+encbuflen, &hmac);
	encbuflen += SHABYTES;		/* MAC */

	if ((rc = sccPutBufferData (req->RequestID, bufidx, encbuf,
			encbuflen)) < 0)
	{
		free (clrbuf);
		free (encbuf);
		return ERR_FAILEDPUTBUFFER;
	}

	incrementseqno (encdata->seqnoout);

	free (clrbuf);
	free (encbuf);
	return 0;
}
