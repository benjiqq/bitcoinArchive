/*
 * rpowutil.c
 *	Generate, read and write reusable proof of work tokens
 */

#include "rpowscc.h"

/*
 * RPOW tokens come in two types.  In transit they are preceded by a type
 * byte and then a four byte value field, which is the equivalent of the
 * hashcash collision size, and must be in the range RPOW_VALUE_MIN to
 * RPOW_VALUE_MAX.  The hashcash type (type 2) then has a four byte length
 * field, and then a version 1 hashcash stamp.  The value in the stamp
 * should equal the earlier value field.
 *
 * The reusable type (type 1) then has a 20 byte keyid.  This is the hash of
 * the public key which issued the token.  It then has a 34 byte token id,
 * of which the last 14 bytes must match the cardid of this card.  Then comes
 * a value signed by the public key identified by the keyid.  The signed
 * value is in a bignum format where it is preceded by a 4-byte byte count.
 * The plaintext of that value consists of the 20 byte SHA-1 hash of the
 * token id, then the byte 2, then is padded to the width of the signing key's
 * modulus modulus.  The padding is done by repeatedly SHA-1 hashing what
 * we have so far and appending the hash, until we have the width we need
 * (the last append just uses the leftmost bytes of the hash).  We then
 * take that value mod the signing key's modulus.  This is what is signed.
 */

#define RPOW_PK_VAL		2
#define POW_EXPIRYSECONDS 14*86400
#define POW_GRACESECONDS 86400
#define MAX_TOK		530


static int rpow_valid_pk (rpow *rp);
static int rpow_valid_pow (rpow *rp);


/* Quick and dirty test for primality */
int
issmallprime (int x)
{
	int p;

	if (x != 2  &&  (x & 1) == 0)
		return 0;
	for (p=3; p<=x/p ; p+=2)
		if (x % p == 0)
			return 0;
	return 1;
}


/* Find the exponent corresponding to the given value */
/* Exponents are consecutive primes starting with pk->e */
int
valuetoexp (gbignum *exp, int value, pubkey *pk)
{
	static int exptab[RPOW_VALUE_MAX-RPOW_VALUE_MIN+1];
	int i;

	if (exptab[0] == 0)
	{
		/* First time; fill exptab with consecutive primes */
		exptab[0] = gbig_to_word (&pk->e);
		for (i=1; i<sizeof(exptab)/sizeof(exptab[0]); i++)
		{
			exptab[i] = exptab[i-1] + 2;
			while (!issmallprime (exptab[i]))
			{
				exptab[i] += 2;
			}
		}
	}
	if (value < RPOW_VALUE_MIN || value > RPOW_VALUE_MAX)
		return -1;
	gbig_from_word (exp, exptab[value-RPOW_VALUE_MIN]);
	return 0;
}


/* Read an rpow value */
rpow *
rpow_read (rpowio *rpio)
{
	rpow *rp = calloc (sizeof(rpow), 1);
	int hclen;
	int value;

	gbig_init (&rp->bn);

	if (rp_read (rpio, &rp->type, 1) != 1)
		goto error;
	if (rp_read (rpio, &value, sizeof(value)) != sizeof(value))
		goto error;
	rp->value = ntohl (value);
	if (rp->value < RPOW_VALUE_MIN || rp->value > RPOW_VALUE_MAX)
		goto error;
	if (rp->type == RPOW_TYPE_HASHCASH)
	{
		if (rp_read (rpio, &hclen, sizeof(hclen)) != sizeof(hclen))
			goto error;
		rp->idlen = ntohl(hclen);
		if (rp->idlen > MAX_TOK)
			goto error;
		rp->id = malloc (rp->idlen + 1);
		if (rp_read (rpio, rp->id, rp->idlen) != rp->idlen)
			goto error;
		rp->id[rp->idlen] = '\0';
	}
	else if (rp->type == RPOW_TYPE_RPOW)
	{
		if (rp_read (rpio, rp->keyid, KEYID_LENGTH) != KEYID_LENGTH)
			goto error;
		rp->id = malloc (RPOW_ID_LENGTH);
		if (rp_read (rpio, rp->id, RPOW_ID_LENGTH) != RPOW_ID_LENGTH)
			goto error;
		if (bnread (&rp->bn, rpio) < 0)
			goto error;
		rp->idlen = RPOW_ID_LENGTH;
	}
	else
		goto error;
	return rp;
error:
	gbig_free (&rp->bn);
	free (rp);
	return NULL;
}

/* Write out an rpow value */
int
rpow_write (rpow *rp, rpowio *rpio)
{
	int value = htonl(rp->value);
	if (rp_write (rpio, &rp->type, 1) != 1)
		return -1;
	if (rp_write (rpio, &value, sizeof(value)) != sizeof(value))
		return -1;
	if (rp->type == RPOW_TYPE_HASHCASH)
	{
		int hclen = htonl(rp->idlen);
		if (rp_write (rpio, &hclen, sizeof(hclen)) != sizeof(hclen))
			return -1;
		if (rp_write (rpio, rp->id, rp->idlen) != rp->idlen)
			return -1;
	} else {	/* rp->type == RPOW_TYPE_RPOW */
		if (rp_write (rpio, rp->keyid, KEYID_LENGTH) != KEYID_LENGTH)
			return -1;
		if (rp_write (rpio, rp->id, rp->idlen) != rp->idlen)
			return -1;
		if (bnwrite (&rp->bn, rpio) < 0)
			return -1;
	}
	return 0;
}


/* Free an rpow */
void
rpow_free (rpow *rp)
{
	if (rp->id)
		free (rp->id);
	gbig_free (&rp->bn);
	free (rp);
}


/* Generate the rpow field of an rpowpend */
static void
rpowpend_bn_gen (gbignum *bn, unsigned char *id, unsigned idlen, pubkey *pk)
{
	unsigned char md[SHA1_DIGEST_LENGTH];
	unsigned char buf[MAXRSAKEYBYTES];
	int nlen = gbig_buflen (&pk->n);
	int off;

	gbig_sha1_buf (buf, id, idlen);
	buf[SHA1_DIGEST_LENGTH] = RPOW_PK_VAL;
	off = SHA1_DIGEST_LENGTH + 1;
	while (off < nlen)
	{
		gbig_sha1_buf (md, buf, off);
		memcpy (buf+off, md, MIN(SHA1_DIGEST_LENGTH, nlen-off));
		off += SHA1_DIGEST_LENGTH;
	}
	gbig_from_buf (bn, buf, nlen);
	gbig_mod (bn, bn, &pk->n);
}


/* Read an rpowpend written by rpowpend_write */
rpowpend *
rpowpend_read (rpowio *rpio)
{
	rpowpend *rpend = calloc (sizeof(rpowpend), 1);
	int value;

	gbig_init (&rpend->rpow);

	rp_read (rpio, &value, sizeof(value));
	rpend->value = ntohl(value);
	if (rpend->value < RPOW_VALUE_MIN || rpend->value > RPOW_VALUE_MAX)
		goto error;
	if (bnread (&rpend->rpow, rpio) < 0)
		goto error;
	return rpend;
error:
	gbig_free (&rpend->rpow);
	free (rpend);
	return NULL;
}


/* Free an rpowpend */
void
rpowpend_free (rpowpend *rpend)
{
	gbig_free (&rpend->rpow);
	free (rpend);
}


/*
 * Validate a POW or RPOW token.  As a side effect, set the fileid.
 */
int
rpow_validate (rpow *rp)
{
	if (rp->type == RPOW_TYPE_HASHCASH)
		return rpow_valid_pow (rp);
	else
		return rpow_valid_pk (rp);
}

/* Given a POW token (hashcash version 1), parse out the fields */
/* Example:  1:15:040719:rpow.net::9e6c82f8e4727a6d:1ec4 */
/* The pointers returned are pointers into the input str */
/* str does not have to be null terminated */
/* Return error if no good */
#define MAXFIELDS	6
static int
pow_parse (const char *str, int len, int *pvalue, time_t *ptime,
		struct tm *ptm, char **presource, char **pparams)
{
	static char str2[MAX_TOK];
	char *pstr = str2;
	char *field[MAXFIELDS];
	int nfields = 0;
	int timelen;
	char *powtime;
	char tbuf[3];

	if (len > MAX_TOK || len < MAXFIELDS
				|| str[0] != '1' || str[1] != ':')
		return RPOW_STAT_INVALID;

	strncpy (str2, str, len);

	while (len--)
	{
		if (*pstr == '\0')
			return RPOW_STAT_INVALID;
		if (*pstr == ':')
		{
			if (nfields+1 > MAXFIELDS)
				return RPOW_STAT_INVALID;
			field[nfields++] = pstr+1;
			*pstr = '\0';
		}
		++pstr;
	}

	if (nfields != MAXFIELDS)
		return RPOW_STAT_INVALID;

	powtime = field[1];
	timelen = strlen (powtime);
	if (timelen < 6)
		return RPOW_STAT_INVALID;

	if (pvalue)
		*pvalue = atoi(field[0]);
	if (presource)
		*presource = field[2];
	if (pparams)
		*pparams = field[3];
	if (ptime)
	{
		memset (ptm, 0, sizeof(*ptm));
		memset (tbuf, 0, sizeof(tbuf));
		strncpy (tbuf, powtime, 2);
		ptm->tm_year = atoi(tbuf) + 100;
		strncpy (tbuf, powtime+2, 2);
		ptm->tm_mon = atoi(tbuf) - 1;
		strncpy (tbuf, powtime+4, 2);
		ptm->tm_mday = atoi(tbuf);
		*ptime = mktime(ptm);
	}
	return RPOW_STAT_OK;
}

static int
rpow_valid_pow (rpow *rp)
{
	int rslt;
	time_t nowtime, powtime;
	struct tm powtm;
	int powvalue;
	char *powresource1;
	unsigned char md[SHA1_DIGEST_LENGTH];
	int i;

	if (rp->value < RPOW_VALUE_MIN || rp->value > RPOW_VALUE_MAX)
		return RPOW_STAT_INVALID;

	/* Parse the POW and see if its fields are legal */
	rslt = pow_parse (rp->id, rp->idlen, &powvalue, &powtime, &powtm,
				&powresource1, NULL);
	if (rslt < 0)
		return rslt;
	if (powvalue != rp->value)
		return RPOW_STAT_INVALID;
	if (strcmp (powresource1, powresource) != 0)
		return RPOW_STAT_BADRESOURCE;
	nowtime = time(0);
	if (powtime > nowtime + POW_GRACESECONDS ||
			powtime < nowtime - POW_EXPIRYSECONDS)
		return RPOW_STAT_BADTIME;

	/* Now test the hash to see if it has the right number of high 0's */
	gbig_sha1_buf (md, rp->id, rp->idlen);
	for (i=0; (i+1)*8<powvalue; i++)
		if (md[i] != 0)
			return RPOW_STAT_INVALID;
	if (md[i] & ~(0xff >> (powvalue&7)))
		return RPOW_STAT_INVALID;

	/* Set the fileid from the month field */
	rp->fileid = powtm.tm_mon % 3;

	return RPOW_STAT_OK;
}


static int
rpow_valid_pk (rpow *rp)
{
	pubkey *pk;
	gbignum paddedid;
	gbignum pow;
	gbignum exp;
	int stat = RPOW_STAT_OK;

	if ((pk = pk_from_keyid (rp->keyid)) == NULL)
		return RPOW_STAT_UNKNOWNKEY;
	if (pk->state == PUBKEY_STATE_INACTIVE)
		return RPOW_STAT_UNKNOWNKEY;
	rp->fileid = pk->fileid;

	/* We only accept id's for our cardid */
	if (memcmp (rp->id + rp->idlen - CARDID_LENGTH, cardid, CARDID_LENGTH)
			!= 0)
		return RPOW_STAT_BADCARDID;

	gbig_init (&paddedid);
	gbig_init (&pow);
	gbig_init (&exp);

	if (valuetoexp (&exp, rp->value, pk) < 0)
	{
		stat = RPOW_STAT_INVALID;
		goto done;
	}
	gbig_mod_exp (&pow, &rp->bn, &exp, &pk->n);
	rpowpend_bn_gen (&paddedid, rp->id, rp->idlen, pk);
	if (gbig_cmp (&pow, &paddedid) != 0)
		stat = RPOW_STAT_INVALID;
done:
	gbig_free (&exp);
	gbig_free (&pow);
	gbig_free (&paddedid);
	return stat;
}
