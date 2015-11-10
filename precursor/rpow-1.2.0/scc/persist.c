/*
 * persist.c
 *	Manage persistent data for IBM 4758 RPOW server
 *
 *	"Nothing in the world can take the place of persistence. Talent will
 *	not; nothing is more common than unsuccessful men with talent. Genius
 *	will not; unrewarded genius is almost a proverb. Education will not;
 *	the world is full of educated derelicts. Persistence and determination
 *	are omnipotent." - Calvin Coolidge
 */

/*
 * 
 * There are many ways to categorize the data used in the RPOW system.
 * One is persistent vs transient.  Persistent data must be preserved
 * across reboots.  A reboot occurs when the power goes away and comes back,
 * or on command from the host.  At a reboot, DRAM memory is cleared and
 * the program restarts from the beginning (from main).  The 4758 has two
 * categories of persistent memory: battery-backed RAM (BBRAM) and flash.
 * Flash has a limited number of write cycles while BBRAM can be written to
 * as many times as desired.  BBRAM is automatically cleared on tamper, while
 * flash is not.  This module is responsible for managing persistent data.
 * 
 * Another way to divide the data is stable versus dynamic.  Dynamic data
 * changes relatively often, while stable data changes seldom.
 * 
 * A third way is sensitive versus non-sensitive.  Sensitive data must be
 * kept secret from the outside world in order for the program to reach its
 * security goals.
 * 
 * Among the persistent data, this gies four possible categories.  We use
 * three of them.  The only one we don't use is persistent, dynamic,
 * sensitive data.  Let us consider the other categories and what is there.
 * 
 * Persistent, dynamic, non-sensitive data includes the external database
 * validation data.  For each external database we track, we maintain a hash
 * tree root, which is in effect a hash of the entire file.  This allows
 * us to validate that the information provided by the host computer is
 * accurate.  We also maintain the depth of the tree as an aide to performing
 * updates.  This data is not sensitive because it is not secret; the host
 * knows what it is.  It changes every time we change the database, which
 * is on every signature issuance, so it is highly dynamic.  And it must
 * persist for the life of the database file, which is potentially forever.
 * We put this data into BBRAM because flash could not handle the number of
 * write cycles we anticipate performing in the lifetime of the software,
 * potentially billions of signature issuances.  We don't manage this data
 * within this module, it is done in the DB validation module.
 * 
 * Persistent, stable, sensitive data includes our private keys.  We have
 * three private keys.  One is the Outbound Authentication key maintained by
 * the IBM OS.  We don't even have access to the private part of that key.
 * It is automatically deleted whenever the software configuration changes.
 * We also have a communications key and our main rpow signing key.  All of
 * these are persistent and sensitive, and change only on key rollover
 * (when we retire an old key and create a new one).  The IBM OS stores
 * the OA private key in BBRAM, and we use that key to encrypt the private
 * parts of our other keys and store them in flash.  Because the OA key is
 * wiped on software configuration change, that also effectively eliminates
 * access to the rpow signing key and the comm key.
 * 
 * Persistent, stable, non-sensitive data includes the public keys that
 * we recognize and accept as RPOW issuers.  These come from two places;
 * one is our previous RPOW signing keys that we have retired in rollovers;
 * and the other is the RPOW signing keys of other cards that are part of
 * the same family and were created via the spawning process.
 *
 */



#include "rpowscc.h"


/*
 * Persistent data.
 * This data is sensitive but hardly ever changes.
 * We store it in flash rom, encrypted with the OA key.
 */
struct rpowdata sdata;

/*
 * This data is not sensitive but hardly ever changes.
 * We store it in flash rom, unencrypted.
 */


/* Names for our persistent data */
static ppd_name_t rpowdatname = {
	'r', 'p', 'o', 'w', 'd', 'a', 't', 'a'
};

static ppd_name_t rpowsigname = {
	'r', 'p', 'o', 'w', 's', 'i', 'g', 'n'
};

static ppd_name_t rpowpubname = {
	'r', 'p', 'o', 'w', 'p', 'u', 'b', ' '
};

/* Persistent data for signing and communications */
struct persistdata *pdata1, *pdata2;
struct persistdata *pdata;

/*
 * Blinding factors for our signing.  Array consists of entries
 * the size of the modulus, r^e and r_inv pairs, one for each
 * exponent.  Generated at keygen time and re-initialized on every
 * reboot.
 */
unsigned char	rpowblind[RPOW_VALUE_COUNT*2*MAXRSAKEYBYTES];

/* Pubkey version of our signing keyid, computed at keygen and reboot */
pubkey rpowsignpk;


/* Set of public keys we support */
/* Actual size of pkeys array is npkeys entries */
struct {
	int				npkeys;
	pubkey			pkeys[1];
}				*pubkeys;
/* Cardid field is also saved with pubkeys structure in flash memory */
/* Card ID is unique across all IBM 4758 cards */
/* And also across all re-initializations of the rpow program */
unsigned char cardid[CARDID_LENGTH];

/* powresource field is based on cardid and ".rpow.net" */
char powresource[2*CARDID_LENGTH + 6 + sizeof(POW_RESOURCE_TAIL)];



/* Compute keyid for pubkey */
void
pk_to_keyid (pubkey *key)
{
	gbig_sha1ctx ctx;
	unsigned char *p;
	int len;
	int nlen;

	gbig_sha1_init (&ctx);

	len = gbig_buflen (&key->n);
	p = malloc (len);
	gbig_to_buf (p, &key->n);
	nlen = htonl(len);
	gbig_sha1_update (&ctx, &nlen, sizeof(nlen));
	gbig_sha1_update (&ctx, p, len);

	len = gbig_buflen (&key->e);
	p = realloc (p, len);
	gbig_to_buf (p, &key->e);
	nlen = htonl(len);
	gbig_sha1_update (&ctx, &nlen, sizeof(nlen));
	gbig_sha1_update (&ctx, p, len);

	gbig_sha1_final (key->keyid, &ctx);
	free (p);
}


/* Called to set up the pubkeys array on reboot */
int
rebootpubkeys (sccOA_CKO_Name_t *certname)
{
	long rc;
	int npk;
	unsigned long pksize = 0;
	rpowio *rpio;
	unsigned char *pubkeybuf;
	int i;

	(void) certname;

	if ((rc = sccGetPPDLen (rpowpubname, &pksize)) != 0)
		return ERR_FAILEDPPD;

	pubkeybuf = malloc (pksize);

	if ((rc = sccGetPPD (rpowpubname, pubkeybuf, pksize)) != 0)
		return ERR_FAILEDPPD;

	rpio = rp_new_from_malloc_buf (pubkeybuf, pksize);
	rp_read (rpio, &npk, sizeof(npk));
	pubkeys = malloc (sizeof(npk) + CARDID_LENGTH + npk * sizeof(pubkey));
	pubkeys->npkeys = npk;
	rp_read (rpio, cardid, CARDID_LENGTH);
	for (i=0; i<npk; i++)
		pubkey_read (&pubkeys->pkeys[i], rpio);

	rp_free (rpio);

	/* Convert cardid to powresource */
	powresource[0] = 0;
	for (i=0; i<8; i++)
		sprintf (powresource+strlen(powresource), "%02x", cardid[i]);
	strcat (powresource, "-");
	for (; i<12; i++)
		sprintf (powresource+strlen(powresource), "%02x", cardid[i]);
	strcat (powresource, "-");
	for (; i<CARDID_LENGTH; i++)
		sprintf (powresource+strlen(powresource), "%02x", cardid[i]);
	strcat (powresource, POW_RESOURCE_TAIL);
	return 0;
}

/* Called to init the pubkeys value on fresh start */
int
initpubkeys ()
{
	long rc;
	pubkeys = malloc (sizeof (pubkeys->npkeys));
	pubkeys->npkeys = 0;
	memset (cardid, 0, CARDID_LENGTH);
	if ((rc = sccSavePPD (rpowpubname, pubkeys,
			sizeof(pubkeys->npkeys) + CARDID_LENGTH, PPD_FLASH)) != 0)
		return ERR_FAILEDPPD;
	return 0;
}

/*
 * Set the cardid and powresource variables.
 * Cardid includes the AdapterID and the boot count when the OA cert
 * was made.
 */
int
setcardid (sccOA_CKO_Name_t *certname)
{
	sccAdapterInfo_t	ainfo;
	unsigned long		ainfosize;
	unsigned long		creation_boot;
	unsigned short		index;
	unsigned			i;

	if (CARDID_LENGTH != sizeof(ainfo.AdapterID)
			+ sizeof(creation_boot) + sizeof(index))
		return ERR_INVALID;
	ainfosize = sizeof(ainfo);
	sccGetConfig (&ainfo, &ainfosize);
	memcpy (cardid, ainfo.AdapterID, sizeof(ainfo.AdapterID));
	creation_boot = htonl (certname->creation_boot);
	index = htons (certname->index);
	memcpy (cardid + sizeof(ainfo.AdapterID), &creation_boot,
			sizeof(creation_boot));
	memcpy (cardid + sizeof(ainfo.AdapterID) + sizeof(creation_boot),
			&index, sizeof(index));

	/* Set the powresource (note, this code is duplicated above) */
	powresource[0] = 0;
	for (i=0; i<8; i++)
		sprintf (powresource+strlen(powresource), "%02x", cardid[i]);
	strcat (powresource, "-");
	for (; i<12; i++)
		sprintf (powresource+strlen(powresource), "%02x", cardid[i]);
	strcat (powresource, "-");
	for (; i<CARDID_LENGTH; i++)
		sprintf (powresource+strlen(powresource), "%02x", cardid[i]);
	strcat (powresource, POW_RESOURCE_TAIL);

	/* Make sure we had enough room in powresource */
	if (strlen(powresource) >= sizeof(powresource)-1)
		return ERR_INVALID;
	return 0;
}



/* Save the pubkeys data into flash */
static int
savepubkeys ()
{
	long rc;
	rpowio *rpio;
	unsigned char *pubkeybuf;
	unsigned pubkeylen;
	int i;

	rpio = rp_new ();
	rp_write (rpio, &pubkeys->npkeys, sizeof (pubkeys->npkeys));
	rp_write (rpio, cardid, CARDID_LENGTH);
	for (i=0; i<pubkeys->npkeys; i++)
		pubkey_write (&pubkeys->pkeys[i], rpio);

	pubkeybuf = rp_buf (rpio, &pubkeylen);

	if ((rc = sccSavePPD (rpowpubname, pubkeybuf, pubkeylen, PPD_FLASH)) != 0)
	{
		rp_free (rpio);
		return ERR_FAILEDPPD;
	}

	rp_free (rpio);
	return 0;
}


/* Called to add a new pubkey that we will support */
/* This does not check for validity, that should be done before */
/* We do check to make sure it is not a duplicate */
int
addpubkey (gbignum *n, int fileid, int state)
{
	int pksize;
	int nkey;
	pubkey pk;
	int i;

	memset (&pk, 0, sizeof(pk));
	gbig_init (&pk.n);
	gbig_init (&pk.e);
	gbig_copy (&pk.n, n);
	gbig_from_word (&pk.e, RPOW_EXP);
	pk.fileid = fileid;
	pk_to_keyid (&pk);
	pk.state = state;

	/* Check for duplicate keyid */
	for (i=0; i<pubkeys->npkeys; i++)
		if (memcmp (pk.keyid, pubkeys->pkeys[i].keyid, KEYID_LENGTH) == 0)
			break;
	if (i < pubkeys->npkeys)
		return ERR_INVALID;

	/* OK, add it */
	if (state == PUBKEY_STATE_SIGNING)
	{
		/* Turn old signing key to ACTIVE */
		for (i=0; i<pubkeys->npkeys; i++)
		{
			if (pubkeys->pkeys[i].state == PUBKEY_STATE_SIGNING)
				pubkeys->pkeys[i].state = PUBKEY_STATE_ACTIVE;
		}
	}
	nkey = pubkeys->npkeys++;
	pksize = sizeof(pubkeys->npkeys) + pubkeys->npkeys * sizeof (pubkey);
	pubkeys = realloc (pubkeys, pksize);
	if (pubkeys == NULL)
		return ERR_NOMEM;
	memcpy (&pubkeys->pkeys[nkey], &pk, sizeof(pk));

	return savepubkeys ();
}

/* Change the state (enable/disable) of an existing key */
int
dochangekeystate (sccRequestHeader_t *req, sccOA_CKO_Name_t *certname)
{
	long			rc;
	unsigned long	keyindex;
	unsigned long	newstate;
	pubkey			*pk;

	if ((rc = sccGetBufferData (req->RequestID, 0, &keyindex,
			sizeof(keyindex))) < 0)
		return ERR_FAILEDGETBUFFER;
	if ((rc = sccGetBufferData (req->RequestID, 1, &newstate,
			sizeof(newstate))) < 0)
		return ERR_FAILEDGETBUFFER;

	pk = pk_from_index (keyindex);
	if (pk == NULL)
		return ERR_INVALID;

	/* Can't change state of signing key */
	if (pk->state == PUBKEY_STATE_SIGNING)
		return ERR_INVALID;

	if (pk->state != newstate)
	{
		pk->state = newstate;
		return savepubkeys ();
	}

	return 0;
}

/* Add a new key which we are asked to trust as a signer */
int
doaddkey (sccRequestHeader_t *req, sccOA_CKO_Name_t *certname)
{
	long			rc;
	unsigned char	*newkeychain;
	unsigned long	newkeychainlen;
	unsigned char	*keybuf;
	unsigned long	keybuflen;
	rpowio			*rpio;
	gbignum			n, e;
	unsigned long	fileid;

	if ((rc = sccGetBufferData (req->RequestID, 0, &fileid,
			sizeof(fileid))) < 0)
		return ERR_FAILEDGETBUFFER;
	if ((rc = checkdbfileid (fileid, 0)) != 0)
		return ERR_INVALID;
	newkeychainlen = req->OutBufferLength[1];
	if (newkeychainlen > 10000)
		return ERR_INVALID;
	newkeychain = malloc (newkeychainlen);
	if (newkeychain == NULL)
		return ERR_NOMEM;
	if ((rc = sccGetBufferData (req->RequestID, 1, newkeychain,
			newkeychainlen)) != 0)
	{
		free (newkeychain);
		return ERR_FAILEDGETBUFFER;
	}

	rc = certvalidate (&keybuf, &keybuflen, newkeychain, newkeychainlen,
			certname);
	if (rc != 0)
	{
		free (newkeychain);
		return ERR_INVALID;
	}

	rpio = rp_new_from_buf (keybuf, keybuflen);
	free (newkeychain);

	/* Ignore first key */
	gbig_init (&n);
	gbig_init (&e);
	if (bnread (&n, rpio) != 0
		|| bnread (&e, rpio) != 0
		|| bnread (&n, rpio) != 0
		|| bnread (&e, rpio) != 0)
	{
		/* Should not happen since we validated the cert chain */
		gbig_free (&n);
		gbig_free (&e);
		rp_free (rpio);
		return ERR_INVALID;
	}
	rp_free (rpio);
	if ((rc = addpubkey (&n, fileid, PUBKEY_STATE_ACTIVE)) != 0)
	{
		gbig_free (&n);
		gbig_free (&e);
		return rc;
	}

	gbig_free (&n);
	gbig_free (&e);

	if ((rc = newdb (certname, fileid)) != 0)
		return rc;

	return 0;
}

/* Find the pubkey in our list of trusted signers corresponding to the keyid */
pubkey *
pk_from_keyid (unsigned char *keyid)
{
	int i;

	/* Search from end to find newest first */
	for (i=pubkeys->npkeys-1; i>=0; --i)
		if (memcmp (pubkeys->pkeys[i].keyid, keyid, KEYID_LENGTH) == 0)
			return &pubkeys->pkeys[i];
	return NULL;
}

pubkey *
pk_from_index (int i)
{
	if (i >= pubkeys->npkeys)
		return NULL;
	return &pubkeys->pkeys[i];
}




/* Called on card reboot to get our secrets from flash memory */
int
rebootsecrets (sccOA_CKO_Name_t *certname)
{
	long				rc;
	sccRSA_RB_t			rsarb;
	int					i;
	sccRSAKeyToken_t	*key;
	unsigned long		keylen;
	unsigned long		encpdatalen = 0;
	unsigned char		*encpdata;

	/* Retrieve OA public key (in a malloc buffer) */
	if ((rc = keyfromcert (&key, &keylen, certname)) != 0)
		return rc;

	/* On a restart we must retrieve our secret prefix from flash */
	if ((rc = sccGetPPD (rpowdatname, &sdata, key->n_Length)) != 0)
	{
		free (key);
		return ERR_FAILEDPPD;
	}

	/* Now we must decrypt it with our OA key */
	memset (&rsarb, 0, sizeof(rsarb));
	rsarb.options = RSA_PRIVATE | RSA_DECRYPT | RSA_DONT_BLIND;
	rsarb.data_in = &sdata;
	rsarb.data_out = &sdata;
	rsarb.data_size = key->n_BitLength;
	free (key);
	key = NULL;
	if ((rc = sccOAPrivOp (certname, &rsarb, sizeof(rsarb))) != 0)
		return ERR_FAILEDRSADECRYPT;

	/* Now we retrieve encrypted persistent keys from flash */
	if ((rc = sccGetPPDLen (rpowsigname, &encpdatalen)) != 0)
		return ERR_FAILEDPPD;

	encpdata = malloc (encpdatalen);

	if ((rc = sccGetPPD (rpowsigname, encpdata, encpdatalen)) != 0)
		return ERR_FAILEDPPD;

	/* Decrypt them to memory */
	if (pdata1)
		free (pdata1);
	pdata1 = malloc (encpdatalen - TDESBYTES);
	if ((rc = tdesdecrypt ((unsigned char *)pdata1, sdata.tdkey,
				encpdata, encpdatalen)) != 0)
	{
		free (encpdata);
		return rc;
	}

	free (encpdata);

	if (PDATALEN(pdata1) + TDESBYTES != encpdatalen)
		return ERR_FAILEDPPD;

	/* Set up for pdata swappage */
	if (pdata2)
		free (pdata2);
	pdata2 = malloc (PDATALEN(pdata1));
	for (i=0; i<PDATALEN(pdata1)/sizeof(unsigned long); i++)
		((unsigned long *)pdata2)[i] = ((unsigned long *)pdata1)[i] ^ ~0L;
	pdata = pdata1;

	setrpowsignpk (&pdata->rpowkey);
	blindgenall ();

	return 0;
}


/*
 * Store our secrets into the flash memory so that we can retrieve
 * them on reboot after power off.
 * We encrypt the secrets using the OA key, ensuring that after any reload
 * of OS or application, which wipes the OA private key, our other secrets
 * are permanently erased.
 * We call this whenever we make a change to the secret data, such as after
 * keygen or also after adding a new database fileid, because those have
 * secret hash prefixes.
 */
int
savesecrets (sccOA_CKO_Name_t *certname)
{
	long				rc;
	sccRSAKeyToken_t	*key;
	sccRSA_RB_t			rsarb;
	unsigned long		keylen;
	unsigned char		encsdata[MAXRSAKEYBYTES];
	unsigned char		*encpdata;
	unsigned long		encpdatalen;

	/* Retrieve OA public key (in a malloc buffer) */
	if ((rc = keyfromcert (&key, &keylen, certname)) != 0)
		return rc;

	/* Choose a random tdes key */
	gbig_rand_bytes (&sdata, key->n_Length);

	/* Now encrypt the data using our OA key */

	/* Make sdata be legal for RSA operations */
	sdata.rsaprefix[0] = 0;
	sdata.rsaprefix[1] = 3;

	memset (&rsarb, 0, sizeof(rsarb));
	rsarb.options = RSA_PUBLIC | RSA_ENCRYPT | RSA_DONT_BLIND;
	rsarb.key_token = key;
	rsarb.key_size = keylen;
	rsarb.data_in = &sdata;
	rsarb.data_out = encsdata;
	rsarb.data_size = key->n_BitLength;

	if ((rc = sccRSA (&rsarb)) != 0)
	{
		free (key);
		return ERR_FAILEDRSAENCRYPT;
	}

	/* Store the encrypted prefix+key in flash */
	if ((rc = sccSavePPD (rpowdatname, encsdata, key->n_Length,
			PPD_FLASH)) != 0)
	{
		free (key);
		return ERR_FAILEDPPD;
	}

	/* Encrypt our persistent signing keys for flash */
	encpdatalen = PDATALEN(pdata) + TDESBYTES;
	encpdata = malloc (encpdatalen);
	if ((rc = tdesencrypt (encpdata, sdata.tdkey,
					(unsigned char *)pdata, PDATALEN(pdata))) != 0)
	{
		free (encpdata);
		free (key);
		return rc;
	}

	/* Store encrypted persistent rpow keys in flash */
	if ((rc = sccSavePPD (rpowsigname, encpdata, encpdatalen,
			PPD_FLASH)) != 0)
	{
		free (encpdata);
		free (key);
		return ERR_FAILEDPPD;
	}

	free (encpdata);
	free (key);
	return 0;
}


/* Call periodically to swap pdata1 and pdata2 to prevent memory burn-in */
void
swappdata ()
{
	int		i;
	int		nl;
	unsigned long d;
	struct persistdata *opdata;

	if (pdata == NULL)
		return;

	opdata = (pdata == pdata1) ? pdata2 : pdata1;

	/* Note that PDATALEN(pdata) is not reliable in the loop */
	nl = PDATALEN(pdata) / sizeof(unsigned long);

	for (i=0; i<nl; i++)
	{
		d = ((unsigned long *)opdata)[i] = ((unsigned long *)pdata)[i];
		((unsigned long *)pdata)[i] = d ^ ~0L;
	}
	pdata = opdata;
}
