/*
 * rpow.c
 *	Reusable Proof of Work implementation for IBM 4758
 */

#include "rpowscc.h"

DEFAGENT;

/* Toggle persistent data to prevent burn-in every this many calls */
#define SWAPCOUNT			20

/* Reset unused POW database field, check at least once every few days */
#define POWRESETCOUNT		8640

/* Time out on waiting for a call this often, to allow burn-in prevention */
#define TIMEOUTMICROSECS	10000000

/* Size of RSA keys we gen for comm and for signing */
#define RSABITS			1024


int dostat (sccRequestHeader_t *req, sccOA_CKO_Name_t *certname,
	sccRSAKeyToken_t *commkey, unsigned long commkeylen);
static int findactivecert (sccOA_CKO_Name_t *certname);
static int cleancerts (void);


sccRequestHeader_t	request;
int					callcount;

int main(int argc,char *argv[])
{
	long				rc;
	sccOA_CKO_Name_t	certname;
	int					havecert = 0;
	int					fileid;
	int					err;

#if defined(DEBUG)
	QMSGHDR       msg;
	unsigned long count;
	int i;

	i = 0;
	memset(&msg,0,sizeof(msg));
	for (;;)
	{
		CPRecvMsg(&msg,&count,0,1000000);
		if (i==1)
			break;
	}
#endif

	if ((rc = sccSignOn(&agentID,NULL)) != 0)
	{
		return rc;
	}

	/* General initialization - setup bignum lib */
	gbig_initialize();

	/* Look for an OA cert.  These get wiped on reload, so if it is present */
	/* then we are just rebooting, and if it is absent this is a fresh load. */
	memset (&certname, 0, sizeof(certname));
	havecert = !findactivecert (&certname);
	if (!havecert)
	{
		/*
		 * Having no cert means that we have been freshly loaded, or there has
		 * been a configuration change (because our certified key is
		 * created as a configuration key, it goes inactive on any reload
		 * of the application or the OS).  We will treat this as an initial
		 * boot.  It shouldn't be necessary, but for safety we will delete
		 * all our persistent data now.  The INITKEYGEN command must be given to
		 * reinitialize everything.
		 */
		sccDeleteAllPPD();
		initdb ();
		initpubkeys ();
	} else {
		/* Finding a cert means we are restarting in a valid state */
		if ((rc = rebootdb(&certname)) != 0 
				|| (rc = rebootpubkeys(&certname)) != 0
				|| (rc = rebootsecrets(&certname)) != 0)
		{
			/* On failure, force re-initialization */
			sccOADelete (&certname);
			sccDeleteAllPPD();
			havecert = 0;
		}
	}

	for(;;)
	{
		err = 0;
		/*
		* Get the next SCC message header
		*/
		rc = sccGetNextHeader(&request, 0, TIMEOUTMICROSECS);

		/* Periodically swap our keys in DRAM to prevent burn-in */
		if (++callcount % SWAPCOUNT == 0)
			swappdata();
		if (havecert && (callcount % POWRESETCOUNT == 0))
			dbresetpow (&certname);

		if (rc != 0)
		{
		  if (rc != QSVCtimedout)
			/*printf("sccGetNextHeader failed 0x%lx\n",rc)*/;
		  continue;
		}

		switch (request.UserDefined)
		{
			case CMD_GETCHAIN:
				if (!havecert)
				{
					err = ERR_UNINITIALIZED;
					break;
				}
				err = dochain (&request, &certname, 0);
				break;
			case CMD_SIGN:
				if (!havecert)
				{
					err = ERR_UNINITIALIZED;
					break;
				}
				err = dosign (&request, &certname,
						&pdata->commkey, pdata->commkeylen,
						&pdata->rpowkey, pdata->rpowkeylen);
				break;
			case CMD_INITKEYGEN:
				/* Eliminate old OA keys so we only have one active one */
				cleancerts ();
				/* Reset other old data */
				sccDeleteAllPPD();
				initdb ();
				initpubkeys ();
				err = dokeygen (&certname, RSABITS, 3, KEYGEN_NEW);
				/* Set up 3 POW dbs and an RPOW db */
				if (err == 0)
					err = newdb (&certname, 0);
				if (err == 0)
					err = newdb (&certname, 1);
				if (err == 0)
					err = newdb (&certname, 2);
				if (err == 0)
					err = newdb (&certname, 3);
				havecert = 1;
				break;
			case CMD_ROLLOVER:
				if (!havecert)
				{
					err = ERR_UNINITIALIZED;
					break;
				}
				if ((rc = sccGetBufferData (request.RequestID, 0, &fileid,
						sizeof(fileid))) < 0)
				{
					err = ERR_FAILEDGETBUFFER;
					break;
				}

				/* Eliminate old OA key */
				cleancerts ();
				err = checkdbfileid (fileid, 1);
				if (err == 0)
					err = dokeygen (&certname, RSABITS, fileid, KEYGEN_ROLL);
				if (err == 0)
					err = newdb (&certname, fileid);
				break;
			case CMD_ADDKEY:
				if (!havecert)
				{
					err = ERR_UNINITIALIZED;
					break;
				}
				err = doaddkey(&request, &certname);
				break;
			case CMD_CHANGEKEYSTATE:
				if (!havecert)
				{
					err = ERR_UNINITIALIZED;
					break;
				}
				err = dochangekeystate(&request, &certname);
				break;
			case CMD_STAT:
				if (!havecert)
				{
					err = ERR_UNINITIALIZED;
					break;
				}
				err = dostat (&request, &certname,
						&pdata->commkey, pdata->commkeylen);
				break;
			case CMD_CLEARLOWBATT:
				/* This value gets latched so this must be called after the
				 * batteries are changed.
				 */
				sccClearLowBatt();
				err = 0;
				break;
			default:
				err = ERR_UNKNOWNCMD;
				break;
		}
		sccEndRequest(request.RequestID, 0, NULL, 0, -err);
	}
	return(0);
}

/* Find an active application configuration key and return its name */
/* Return -1 if we can't find one, 0 on success */
static int
findactivecert (sccOA_CKO_Name_t *certname)
{
	long				rc;
	unsigned long		certCount;
	unsigned long		certDirLen;
	unsigned long		i;
	sccOA_DirItem_t		*certDir;

	certCount = certDirLen = 0;
	if ((rc = sccOAGetDir (&certCount, NULL, &certDirLen)) != 0)
	{
		return -1;
	}

	if ((certDir = malloc(UP4(certDirLen))) == NULL)
	{
		return -1;
	}

	if ((rc = sccOAGetDir (&certCount, certDir, &certDirLen)) != 0)
	{
		free (certDir);
		return -1;
	}

	for (i=0; i<certCount; i++)
	{
		if (certDir[i].cko_status == OA_CKO_ACTIVE
			&& certDir[i].cko_type == OA_CKO_SEG3_CONFIG)
			break;
	}

	if (i < certCount)
		*certname = certDir[i].cko_name;

	free (certDir);

	return (i < certCount) ? 0 : -1;
}

/* Eliminate other SEG3 certs, active or inactive */
static int
cleancerts ()
{
	long				rc;
	unsigned long		certCount;
	unsigned long		certDirLen;
	unsigned long		i;
	sccOA_DirItem_t		*certDir;

	certCount = certDirLen = 0;
	if ((rc = sccOAGetDir (&certCount, NULL, &certDirLen)) != 0)
	{
		return -1;
	}

	if ((certDir = malloc(UP4(certDirLen))) == NULL)
	{
		return -1;
	}

	if ((rc = sccOAGetDir (&certCount, certDir, &certDirLen)) != 0)
	{
		free (certDir);
		return -1;
	}

	for (i=0; i<certCount; i++)
	{
		if (certDir[i].cko_type == OA_CKO_SEG3_CONFIG
				|| certDir[i].cko_type == OA_CKO_SEG3_EPOCH)
			sccOADelete (&certDir[i].cko_name);
	}

	free (certDir);

	return 0;
}

/* Return general status information on the card, memory usage, battery state, etc. */
int
dostat (sccRequestHeader_t *req, sccOA_CKO_Name_t *certname,
	sccRSAKeyToken_t *commkey, unsigned long commkeylen)
{
	long				rc;
	struct encstate		encdata;
	unsigned char		*buf;
	unsigned			off;
	unsigned long		bufsize = 0;
	unsigned long		ppdspace;
	int					npkeys;
	int					i;
	pubkey				*pk;

	if ((rc = sccGetConfig (NULL, &bufsize)) != 0)
		return ERR_FAILEDOTHER;
	buf = malloc (sizeof(unsigned long) + UP4(bufsize));
	if (buf == NULL)
		return ERR_NOMEM;
	memset (buf, 0, sizeof(unsigned long) + UP4(bufsize));
	off = 0;
	*(unsigned long *)(buf+off) = htonl(bufsize);
	off += sizeof(unsigned long);
	if ((rc = sccGetConfig ((sccAdapterInfo_t *)(buf+off), &bufsize)) != 0)
		return ERR_FAILEDOTHER;
	off += UP4(bufsize);

	if ((rc = sccOAStatus (NULL, &bufsize)) != 0)
		return ERR_FAILEDOTHER;
	buf = realloc (buf, off + sizeof(unsigned long) + UP4(bufsize));
	if (buf == NULL)
		return ERR_NOMEM;
	memset (buf+off, 0, sizeof(unsigned long) + UP4(bufsize));
	*(unsigned long *)(buf+off) = htonl(bufsize);
	off += sizeof(unsigned long);
	if ((rc = sccOAStatus (buf+off, &bufsize)) != 0)
		return ERR_FAILEDOTHER;
	off += UP4(bufsize);

	bufsize = sizeof(TIME_BLOCK);
	buf = realloc (buf, off + sizeof(unsigned long) + UP4(bufsize));
	if (buf == NULL)
		return ERR_NOMEM;
	memset (buf+off, 0, sizeof(unsigned long) + UP4(bufsize));
	*(unsigned long *)(buf+off) = htonl(bufsize);
	off += sizeof(unsigned long);
	if ((rc = CPGetTime (buf+off)) != 0)
		return ERR_FAILEDOTHER;
	off += UP4(bufsize);

	bufsize = 2*sizeof(unsigned long);
	buf = realloc (buf, off + sizeof(unsigned long) + UP4(bufsize));
	if (buf == NULL)
		return ERR_NOMEM;
	memset (buf+off, 0, sizeof(unsigned long) + UP4(bufsize));
	*(unsigned long *)(buf+off) = htonl(bufsize);
	off += sizeof(unsigned long);
	if ((rc = sccQueryPPDSpace (&ppdspace, PPD_FLASH)) != 0)
		return ERR_FAILEDOTHER;
	*(unsigned long *)(buf+off) = htonl(ppdspace);
	off += sizeof(unsigned long);
	if ((rc = sccQueryPPDSpace (&ppdspace, PPD_BBRAM)) != 0)
		return ERR_FAILEDOTHER;
	*(unsigned long *)(buf+off) = htonl(ppdspace);
	off += sizeof(unsigned long);

	for (npkeys=0; pk_from_index(npkeys); npkeys++)
		;
	bufsize = npkeys * (KEYID_LENGTH+2*sizeof(unsigned long));
	buf = realloc (buf, off + sizeof(unsigned long) + UP4(bufsize));
	if (buf == NULL)
		return ERR_NOMEM;
	memset (buf+off, 0, sizeof(unsigned long) + UP4(bufsize));
	*(unsigned long *)(buf+off) = htonl(bufsize);
	off += sizeof(unsigned long);
	for (i=0; i<npkeys; i++)
	{
		pk = pk_from_index (i);
		memcpy (buf+off, pk->keyid, KEYID_LENGTH);
		off += KEYID_LENGTH;
		*(unsigned long *)(buf+off) = htonl (pk->fileid);
		off += sizeof(unsigned long);
		*(unsigned long *)(buf+off) = htonl (pk->state);
		off += sizeof(unsigned long);
	}

	/* Encrypt data and return it */
	if ((rc = decryptmaster (&encdata, req, commkey, commkeylen, 0)) != 0
		|| (rc = encryptoutput (&encdata, buf, off, req, 0)) != 0)
	{
		free (buf);
		return rc;
	}

	free (buf);
	return 0;
}

