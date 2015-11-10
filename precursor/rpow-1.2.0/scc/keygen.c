/* Gen an OA key and return its cert chain */

#include "rpowscc.h"

static sccRSAKeyGen_RB_t		rsarb;


/* Generate blinding factors for a signing key */
/* Array consists of r^e, r_inv, each the size of the modulus */
static void
blindgen (sccRSAKeyToken_t *key, gbignum *mod, gbignum *exp, gbignum *phi1,
	unsigned char *pblind)
{
	gbignum bnr, bnrinv, bnre;

	gbig_init (&bnr);
	gbig_init (&bnrinv);
	gbig_init (&bnre);

	gbig_rand_range (&bnr, &gbig_value_zero, mod);
	gbig_mod_exp (&bnrinv, &bnr, phi1, mod);
	gbig_mod_exp (&bnre, &bnr, exp, mod);
	gbig_to_buf_len (pblind, key->n_Length, &bnre);
	gbig_to_buf_len (pblind+key->n_Length, key->n_Length, &bnrinv);

	gbig_free (&bnr);
	gbig_free (&bnrinv);
	gbig_free (&bnre);
}


/*
 * Generate blinding factors for all signing exponents.  This is only
 * used on boot or on keygen.
 * Then the 4758 function generates new blinding factors after each
 * use.
 */
void
blindgenall ()
{
	sccRSAKeyToken_t	*key = &pdata->rpowkey;
	unsigned char		*ckey = (unsigned char *)key;
	int					i;
	int					e = 65537;
	gbignum				bne;
	gbignum				pm1, qm1;
	gbignum				phi1;
	gbignum				n;

	gbig_init (&bne);
	gbig_init (&pm1);
	gbig_init (&qm1);
	gbig_init (&phi1);
	gbig_init (&n);

	gbig_from_buf (&pm1, ckey+key->y.p_Offset, key->x.p_Length);
	gbig_from_buf (&qm1, ckey+key->q_Offset, key->q_Length);
	gbig_sub (&pm1, &pm1, &gbig_value_one);
	gbig_sub (&qm1, &qm1, &gbig_value_one);
	gbig_mul (&phi1, &pm1, &qm1);
	gbig_sub (&phi1, &phi1, &gbig_value_one);

	gbig_from_buf (&n, ckey+key->n_Offset, key->n_Length);

	for (i=0; i<RPOW_VALUE_COUNT; i++)
	{
		gbig_from_word (&bne, e);
		blindgen (key, &n, &bne, &phi1, rpowblind + i*2*key->n_Length);
		do {
			e = e + 2;
		} while (!issmallprime(e));
	}

	gbig_free (&bne);
	gbig_free (&pm1);
	gbig_free (&qm1);
	gbig_free (&phi1);
	gbig_free (&n);
}

/* Generate dp dq array for rpow key */
/* Each represents a d value for e values that are consecutive primes */
static void
dpqgen (sccRSAKeyToken_t *key, unsigned char *dpq)
{
	unsigned char		*ckey = (unsigned char *)key;
	int					i;
	int					e = 65537;
	gbignum				p;
	gbignum				q;
	gbignum				pm1;
	gbignum				qm1;
	gbignum				bne;
	gbignum				bnd;

	gbig_init (&p);
	gbig_init (&q);
	gbig_init (&pm1);
	gbig_init (&qm1);
	gbig_init (&bne);
	gbig_init (&bnd);

	gbig_from_buf (&p, ckey+key->y.p_Offset, key->x.p_Length);
	gbig_from_buf (&q, ckey+key->q_Offset, key->q_Length);

	gbig_sub (&pm1, &p, &gbig_value_one);
	gbig_sub (&qm1, &q, &gbig_value_one);

	for (i=0; i<RPOW_VALUE_COUNT; i++)
	{
		gbig_from_word (&bne, e);
		gbig_mod_inverse (&bnd, &bne, &pm1);
		gbig_to_buf_len (dpq, key->n_Length/2, &bnd);
		dpq += key->n_Length/2;
		
		gbig_from_word (&bne, e);
		gbig_mod_inverse (&bnd, &bne, &qm1);
		gbig_to_buf_len (dpq, key->n_Length/2, &bnd);
		dpq += key->n_Length/2;

		do {
			e = e + 2;
		} while (!issmallprime(e));
	}

	gbig_free (&p);
	gbig_free (&q);
	gbig_free (&pm1);
	gbig_free (&qm1);
	gbig_free (&bne);
	gbig_free (&bnd);
}

/* Check that the key is suitable for use as an rpow key */
/* We want to make sure p-1 and q-1 are relatively prime to many values */
/* Return 0 if OK, nonzero otherwise */
static int
keyokforrpow (sccRSAKeyToken_t *key)
{
	unsigned char		*ckey = (unsigned char *)key;
	gbignum				p;
	gbignum				q;
	gbignum				t1;
	gbignum				bne;
	int					e = 65537;
	int					i;

	/* Require dp and dq to be exactly half the modulus length */
	if (key->dpLength != key->n_Length/2 || key->dqLength != key->n_Length/2)
		return -1;

	/* Require r and r1 to be exactly the modulus length */
	if (key->r_Length != key->n_Length || key->r1Length != key->n_Length)
		return -1;

	gbig_init (&p);
	gbig_init (&q);
	gbig_init (&t1);
	gbig_init (&bne);

	gbig_from_buf (&p, ckey+key->y.p_Offset, key->x.p_Length);
	gbig_from_buf (&q, ckey+key->q_Offset, key->q_Length);

	/* Make sure p, q mod x is not 1 for all small primes */
	for (i=0; i<RPOW_VALUE_COUNT; i++)
	{
		gbig_from_word (&bne, e);
		gbig_mod (&t1, &p, &bne);
		if (gbig_cmp (&t1, &gbig_value_one) == 0)
			break;
		gbig_mod (&t1, &q, &bne);
		if (gbig_cmp (&t1, &gbig_value_one) == 0)
			break;
		do {
			e = e + 2;
		} while (!issmallprime(e));
	}

	gbig_free (&p);
	gbig_free (&q);
	gbig_free (&t1);
	gbig_free (&bne);

	return (i == RPOW_VALUE_COUNT) ? 0 : -1;
}

/* Generate an RSA key and then put its public part into the pubbuf */
/* Caller supplies an adequately sized buffer, *pkeylen holds its length */
static int
rsakeygen (sccRSAKeyToken_t *key, unsigned long *pkeylen,
	unsigned long *ppublen, int size, unsigned char *pubbuf, unsigned long pubbuflen)
{
	long				rc;
	unsigned char		*ptr;
	unsigned char		*nPtr;
	unsigned char		*ePtr;

	memset (key, 0, sizeof(sccRSAKeyToken_t));

	memset (&rsarb, 0, sizeof(rsarb));
	rsarb.key_type = RSA_PRIVATE_CHINESE_REMAINDER;
	rsarb.mod_size = size;
	rsarb.public_exp = RSA_EXPONENT_65537;
	rsarb.key_token = key;
	rsarb.key_size = pkeylen;

	if ((rc = sccRSAKeyGenerate (&rsarb)) != 0)
	{
		free (key);
		return ERR_FAILEDGENERATE;
	}

	if (key->n_Length + key->e_Length + 2*sizeof(unsigned long) > pubbuflen)
	{
		free (key);
		return ERR_INVALID;
	}

	/* Store modulus and exponent fields for OA generate */
	/* Precede them with four byte count, bigendian */
	nPtr = (unsigned char *)key + key->n_Offset;
	ePtr = (unsigned char *)key + key->e_Offset;
	ptr = pubbuf;
	*(unsigned long *)ptr = htonl(key->n_Length);
	ptr += sizeof(unsigned long);
	memcpy (ptr, nPtr, key->n_Length);
	ptr += key->n_Length;
	*(unsigned long *)ptr = htonl(key->e_Length);
	ptr += sizeof(unsigned long);
	memcpy (ptr, ePtr, key->n_Length);
	ptr += key->e_Length;

	*ppublen = ptr - pubbuf;
	return 0;
}


/* Add the pubkey value from our private key */
static int
addpubkeyfrompriv (sccRSAKeyToken_t *key, int fileid)
{
	int 				rc;
	unsigned char		*ckey = (unsigned char *)key;
	gbignum				n;

	gbig_init (&n);
	gbig_from_buf (&n, ckey+key->n_Offset, key->n_Length);
	rc = addpubkey (&n, fileid, PUBKEY_STATE_SIGNING);
	gbig_free (&n);
	return rc;
}

/* Set the pubkey version of current signing key */
void
setrpowsignpk (sccRSAKeyToken_t *key)
{
	unsigned char		*ckey = (unsigned char *)key;

	memset (&rpowsignpk, 0, sizeof(rpowsignpk));
	gbig_from_buf (&rpowsignpk.n, ckey+key->n_Offset, key->n_Length);
	gbig_from_buf (&rpowsignpk.e, ckey+key->e_Offset, key->e_Length);
	pk_to_keyid (&rpowsignpk);
}


/* Generate an OA key and return its name */
int
dokeygen (sccOA_CKO_Name_t *certname, int size, int fileid, int newflag)
{
	long				rc;
	struct {
		sccOAGen_RB_t		rb;
		unsigned char		keydata[4*(4+MAXRSAKEYBYTES) + CARDID_LENGTH];
	}					oarb;
	unsigned long		commkeydatalen;
	unsigned long		rpowkeydatalen;

	memset (&oarb, 0, sizeof(oarb));

	if (pdata1 == NULL)
	{
		pdata1 = calloc (sizeof (struct persistdata), 1);
		pdata2 = calloc (sizeof (struct persistdata), 1);
		pdata = pdata1;
	}

	/*
	 * First we will generate two regular keys, then an OA key with
	 * those keys embedded in it
	 */

	pdata->commkeylen = sizeof(pdata->commkey)
						+ sizeof(pdata->commkeydata);
	if ((rc = rsakeygen (&pdata->commkey, &pdata->commkeylen,
			&commkeydatalen, size, oarb.keydata, sizeof(oarb.keydata))) != 0)
		return rc;
	do {
		pdata->rpowkeylen = sizeof(pdata->rpowkey)
						+ sizeof(pdata->rpowkeydata);
		if ((rc = rsakeygen (&pdata->rpowkey, &pdata->rpowkeylen,
			&rpowkeydatalen, size, oarb.keydata+commkeydatalen,
						sizeof(oarb.keydata)-commkeydatalen)) != 0)
			return rc;
	} while (keyokforrpow (&pdata->rpowkey) != 0);

	/* Generate dp, dq values for other exponents for rpowkey */
	dpqgen (&pdata->rpowkey, pdata->rpowdpq);

	/*
	 * Here is the problem.  We want to put out card ID into the cert chain.
	 * But the card ID must be unique for every instantiation of the program,
	 * including re-initializations.  We can't know reliably what instantiation
	 * number we are based on our own data, because any persistent data might
	 * have been left by a malicious program.  We can't trust anything on
	 * reload unless our OA key is still intact, because as a configuration
	 * key it will be erased on any software reload.  So if we start fresh,
	 * with a new OA key, we can't trust any persistent data, hence we can't
	 * know how many reloads we have had.  So we can't, on our own, create
	 * a cardid which is guaranteed unique across reloads.
	 *
 	 * The solution is to use the boot counter along with the OA manager's
	 * index value.  It is guaranteed to be unique.  Unfortunately the only
	 * way to get it is to generate an OA key.  But we want to put the data
	 * into the OA key certificate!
	 *
	 * Therefore we will generate two OA keys.  We will generate the first
	 * one and extract the boot counter information to generate a guaranteed
	 * unique card id based on the concatenation of our AdapterID and the
	 * boot counter plus index.  This we will put into the cardid field.
	 * Then we will discard that OA key and generate the persistent one,
	 * which will include the cardid along with the RSA keys generated
	 * above in the certificate.  This way we will be able to propagate
	 * our cardid in the one certificate we create, and it will still be
	 * guaranteed unique.
	 */

	if (newflag)
	{
		/* Generate a throw-away OA key just to get a unique instance ID */
		oarb.rb.struct_id.name = SCCOAGEN_RB_T;
		oarb.rb.struct_id.version = SCCOAGEN_RB_VER;
		oarb.rb.algorithm = OA_RSA;
		oarb.rb.cko_type = OA_CKO_SEG3_CONFIG;
		oarb.rb.vSeg3Field.offset = 0;
		oarb.rb.vSeg3Field.len = 0;
		oarb.rb.pCKO_name = certname;

		memset (&rsarb, 0, sizeof(rsarb));
		rsarb.key_type = RSA_PRIVATE_CHINESE_REMAINDER;
		rsarb.mod_size = size;
		rsarb.public_exp = RSA_EXPONENT_65537;
		if ((rc = sccOAGenerate (&oarb.rb, sizeof(oarb.rb),
			&rsarb, sizeof(rsarb))) != 0)
		{
			return ERR_FAILEDOA;
		}

		/* Set the cardid from that OA cert, and then delete it */
		if ((rc = setcardid (certname)) != 0)
			return rc;

		sccOADelete (certname);
	}

	/* Now generate the "real" OA key */

	/* Add our card ID to the authenticated key data */
	memcpy (oarb.keydata+commkeydatalen+rpowkeydatalen, cardid, CARDID_LENGTH);

	/* Generate the OA key embedding our keys */
	oarb.rb.struct_id.name = SCCOAGEN_RB_T;
	oarb.rb.struct_id.version = SCCOAGEN_RB_VER;
	oarb.rb.algorithm = OA_RSA;
	oarb.rb.cko_type = OA_CKO_SEG3_CONFIG;
	oarb.rb.vSeg3Field.offset =
					oarb.keydata - (unsigned char *)&oarb.rb.vSeg3Field;
	oarb.rb.vSeg3Field.len = commkeydatalen+rpowkeydatalen+CARDID_LENGTH;
	oarb.rb.pCKO_name = certname;

	memset (&rsarb, 0, sizeof(rsarb));
	rsarb.key_type = RSA_PRIVATE_CHINESE_REMAINDER;
	rsarb.mod_size = size;
	rsarb.public_exp = RSA_EXPONENT_65537;
	if ((rc = sccOAGenerate (&oarb.rb, sizeof(oarb.rb)+oarb.rb.vSeg3Field.len,
		&rsarb, sizeof(rsarb))) != 0)
	{
		return ERR_FAILEDOA;
	}


	/* Add a new pubkey item from the new private key */
	addpubkeyfrompriv (&pdata->rpowkey, fileid);
	/* Set the global variable holding our new signing key id */
	setrpowsignpk (&pdata->rpowkey);
	/* Generate blinding factors for all exponents of the signing key */
	blindgenall ();

	/* Update secret data in flash */
	savesecrets (certname);

	return 0;
}


/*
 * Get the cert chain that validates the named cert.
 * Return in a malloc buffer *pcertbuf, setting *pcertbuflen.
 */
int
getcertchain (unsigned char **pcertbuf, unsigned long *pcertbuflen,
	sccOA_CKO_Name_t *certname)
{
	long				rc;
	unsigned long		certlen;
	unsigned long		certbuflen;
	unsigned char		*certbuf;
	unsigned char		*certptr;
	sccOA_CKO_Head_t	*cert;
	sccOA_CKO_Name_t	*parentname;
	int					n;

	if ((rc = sccOAGetCert(certname, NULL, &certlen)) != 0)
	{
		return ERR_FAILEDGETCERT;
	}

	certbuflen = certlen;
	certptr = certbuf = malloc(UP4(certbuflen));
	memset (certbuf, 0, UP4(certbuflen));

	if ((rc = sccOAGetCert(certname, certptr, &certlen)) != 0)
	{
		free (certbuf);
		return ERR_FAILEDGETCERT;
	}

	for (n=0; ; n++)
	{
		cert = (sccOA_CKO_Head_t *) certptr;
		parentname = &cert->parent_name;
		if (parentname->name_type == OA_IBM_ROOT)
			break;

		if ((rc = sccOAGetCert(parentname, NULL, &certlen)) != 0)
		{
			free (certbuf);
			return ERR_FAILEDGETCERT;
		}

		certbuf = realloc (certbuf, UP4(certbuflen+certlen));
		certptr = certbuf + certbuflen;
		memset (certptr, 0, UP4(certbuflen+certlen)-certbuflen);
		certbuflen += certlen;

		if ((rc = sccOAGetCert(parentname, certptr, &certlen)) != 0)
		{
			free (certbuf);
			return ERR_FAILEDGETCERT;
		}
	}

	*pcertbuf = certbuf;
	*pcertbuflen = certbuflen;
	return 0;
}

/* Send the host the hash chain for the named key */
int
dochain (sccRequestHeader_t *req, sccOA_CKO_Name_t *certname, int bufidx)
{
	long				rc;
	unsigned char		*certbuf;
	unsigned long		certbuflen;

	if ((rc = getcertchain (&certbuf, &certbuflen, certname)) != 0)
		return rc;

	if ((rc = sccPutBufferData (req->RequestID, bufidx,
					certbuf, UP4(certbuflen))) != 0)
	{
		free (certbuf);
		return ERR_FAILEDPUTBUFFER;
	}

    free (certbuf);
	return 0;
}
