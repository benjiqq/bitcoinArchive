/*
 * rpowsign.c
 *	Perform the signature function for RPOW
 */

#include "rpowscc.h"

/* Maximum allowed rpows at a time */
#define MAXCOUNT	10


int privkey_rawsign (gbignum *rslt, gbignum *val, sccRSAKeyToken_t *key, int keylen, int expnum);


/* Implement the rpow signature function */
int
dosign (sccRequestHeader_t *req, sccOA_CKO_Name_t *certname,
		sccRSAKeyToken_t *commkey, unsigned long commkeylen,
		sccRSAKeyToken_t *key, unsigned long keylen)
{
	long rc;
	struct encstate encdata;
	rpow **rp = NULL;
	rpowpend **rpend = NULL;
	rpowio *rpio;
	gbignum *reply = NULL;
	gbignum tmp1;
	gbignum invalue;
	gbignum outvalue;
	int rpicount, rpocount;
	int i;
	int found;
	unsigned char stat;
	unsigned char *buf = NULL;
	unsigned long buflen;
	unsigned char signkeyid[KEYID_LENGTH];

	gbig_init (&tmp1);
	gbig_init (&invalue);
	gbig_init (&outvalue);

	/* First do the RSA decryption on input data */
	if ((rc = decryptmaster (&encdata, req, commkey, commkeylen, 0)) < 0)
		return rc;

	/* Then the TDES decryption on the rest */
	if ((rc = decryptinput (&buf, &buflen, &encdata, req, 1)) < 0)
		return rc;

	stat = RPOW_STAT_BADFORMAT;

	if (buflen == 0)
	{
		if (buf)
			free (buf);
		goto input_error1;
	}

	/* Create our pointer for reading from this buffer */
	/* buf now belongs to this rpio */
	rpio = rp_new_from_malloc_buf (buf, buflen);

	if (rp_read (rpio, &signkeyid, sizeof(signkeyid)) != sizeof(signkeyid))
		goto input_error;

	if (memcmp (signkeyid, rpowsignpk.keyid, sizeof(signkeyid)) != 0)
	{
		stat = RPOW_STAT_WRONGKEY;
		goto input_error;
	}

	if (rp_read (rpio, &rpicount, sizeof(rpicount)) != sizeof(rpicount))
		goto input_error;
	rpicount = ntohl(rpicount);
	if (rpicount > MAXCOUNT || rpicount <= 0)
		goto input_error;
	rp = calloc (rpicount * sizeof (rpow *), 1);
	if (rp == NULL)
		goto input_error;
	gbig_from_word (&invalue, 0);

	/* Read and verify the incoming rpows */
	for (i=0; i<rpicount; i++)
	{
		rp[i] = rpow_read (rpio);
		if (rp[i] == NULL)
			goto input_error;
		stat = rpow_validate (rp[i]);
		if (stat == RPOW_STAT_OK)
		{
			/* Check the seen-rpow database */
			if ((rc = testdbandset (&found, req, rp[i]->id, rp[i]->idlen,
					rp[i]->fileid)) != 0)
				return rc;			/* host lied, should not happen */
			if (found)
				stat = RPOW_STAT_REUSED;
		}

		if (stat != RPOW_STAT_OK)
			goto input_error;
		stat = RPOW_STAT_BADFORMAT;
		gbig_from_word (&tmp1, 0);
		gbig_set_bit (&tmp1, rp[i]->value);
		gbig_add (&invalue, &invalue, &tmp1);
	}
	if (rp_read (rpio, &rpocount, sizeof(rpocount)) != sizeof(rpocount))
		goto input_error;
	rpocount = ntohl(rpocount);
	if (rpocount > MAXCOUNT || rpocount <= 0)
		goto input_error;
	rpend = calloc (rpocount * sizeof (rpowpend *), 1);
	if (rpend == NULL)
		goto input_error;
	reply = calloc (rpocount * sizeof (gbignum), 1);
	if (reply == NULL)
		goto input_error;
	for (i=0; i<rpocount; i++)
		gbig_init (&reply[i]);
	gbig_from_word (&outvalue, 0);

	/* Read the outgoing rpowpend values to be signed */
	for (i=0; i<rpocount; i++)
	{
		rpend[i] = rpowpend_read (rpio);
		if (rpend[i] == NULL)
			goto input_error;
		gbig_from_word (&tmp1, 0);
		gbig_set_bit (&tmp1, rpend[i]->value);
		gbig_add (&outvalue, &outvalue, &tmp1);
	}

	/* Make sure the incoming value == outgoing */
	if (gbig_cmp (&invalue, &outvalue) != 0)
	{
		stat = RPOW_STAT_MISMATCH;
		goto input_error;
	}

	/* Everything is OK, sign the requested values */
	for (i=0; i<rpocount; i++)
	{
		/* Compute rpend[i]->rpow^d mod n using the CRT */
		if ((rc = privkey_rawsign (&reply[i], &rpend[i]->rpow, key, keylen,
						rpend[i]->value-RPOW_VALUE_MIN)) != 0)
		{
			stat = RPOW_STAT_BADRPEND;
			goto input_error;
		}
	}

	stat = RPOW_STAT_OK;

input_error:

	/* Prepare to write results to caller */
	rp_free (rpio);
input_error1:
	rpio = rp_new ();

	if (rp_write (rpio, &stat, 1) < 0)
	{
		rc = ERR_NOMEM;
		goto done;
	}
	if (stat == RPOW_STAT_OK)
	{
		for (i=0; i<rpocount; i++)
		{
			if (bnwrite (&reply[i], rpio) < 0)
			{
				rc = ERR_NOMEM;
				goto done;
			}
		}
	}

	buf = rp_buf (rpio, (unsigned *)&buflen);

	if ((rc = encryptoutput (&encdata, buf, buflen, req, 0)) != 0)
		goto done;

	rc = 0;
	
done:
	rp_free (rpio);

	if (rp)
	{
		for (i=0; i<rpicount; i++)
		{
			if (rp[i])
				rpow_free (rp[i]);
		}
		free (rp);
	}
	if (rpend)
	{
		for (i=0; i<rpocount; i++)
		{
			if (rpend[i])
				rpowpend_free (rpend[i]);
		}
		free (rpend);
	}
	if (reply)
	{
		for (i=0; i<rpocount; i++)
		{
			gbig_free (&reply[i]);
		}
		free (reply);
	}
	gbig_free (&tmp1);
	gbig_free (&invalue);
	gbig_free (&outvalue);

	return rc;
}

/* Do a sign operation using the specified exponent */
int
privkey_rawsign (gbignum *rslt, gbignum *val, sccRSAKeyToken_t *key, int keylen, int expnum)
{
	long			rc;
	unsigned char	*ckey = (unsigned char *)key;
	sccRSA_RB_t		rb;
	unsigned char	data[MAXRSAKEYBYTES];
	unsigned		len;

	/* Copy dp and dq to the key */
	memcpy (ckey+key->dpOffset, pdata->rpowdpq+(2*expnum)*key->n_Length/2,
			key->n_Length/2);
	memcpy (ckey+key->dqOffset, pdata->rpowdpq+(2*expnum+1)*key->n_Length/2,
			key->n_Length/2);

	/* Copy blinding factors to the key */
	memcpy (ckey+key->r_Offset, rpowblind+(2*expnum)*key->n_Length,
			key->n_Length);
	memcpy (ckey+key->r1Offset, rpowblind+(2*expnum+1)*key->n_Length,
			key->n_Length);

	/* Check for input value of 0 - defense against timing attacks */
	gbig_mod (val, val, &rpowsignpk.n);
	if (gbig_cmp (val, &gbig_value_zero) == 0)
	{
		gbig_free (rslt);
		return 0;
	}

	/* Put val into buffer */
	len = gbig_buflen (val);
	if (len > sizeof (data))
		return ERR_INVALID;
	gbig_to_buf_len (data, key->n_Length, val);

	memset (&rb, 0, sizeof(rb));
	rb.options = RSA_PRIVATE | RSA_DECRYPT | RSA_BLIND_NO_UPDATE;
	rb.key_token = key;
	rb.key_size = keylen;
	rb.data_in = data;
	rb.data_out = data;
	rb.data_size = key->n_BitLength;
	if ((rc = sccRSA(&rb)) != 0)
		return ERR_FAILEDRSASIGN;

	/* Copy blinding factors out of the key */
	memcpy (rpowblind+(2*expnum)*key->n_Length, ckey+key->r_Offset,
			key->n_Length);
	memcpy (rpowblind+(2*expnum+1)*key->n_Length, ckey+key->r1Offset,
			key->n_Length);

	gbig_from_buf (rslt, data, key->n_Length);
	return 0;
}
