/*
 * dbverify.c
 *	Verify the correctness of updates to an off-card database
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <qsvccnst.h>
#include <rslbswap.h>
#include "rpowscc.h"

#ifndef UP4
#define UP4(n)	((((n)+3)/4)*4)
#endif


typedef unsigned char uchar;
typedef unsigned long ulong;

/*
 * Database is formatted as a btree.
 * Leaf nodes have from NODEKEYS/2 to NODEKEYS keys.
 * Each inner node has from NODEKEYS/2 to NODEKEYS keys,
 * and one more child than keys.
 * Top node has from 2 to NODEKEYS children.
 * We start up with 1 top node with 1 child, 1 empty leaf node.
 */

/* Number of keys per node, must be even */
#define NODEKEYS	100

#define NONLEAF		0
#define ISLEAF		1

#define htonl	rswapl
#define htons	rswaps
#define ntohl	rswapl
#define ntohs	rswaps
#define assert(x)


/* Our DB proof structure from the host is an array of these */
/* We allow NODEKEYS+1 keys in a node temporarily but will split it */
typedef struct compnode {
	ulong nkeys;
	ulong keyind;
	uchar hashdata[1][HASHSIZE];	/* Actually 2*nkeys+1 hashes */
									/* First, nkeys key hashes, then */
									/* if non-leaf, nkeys+1 childhashes */
} compnode;

/* Compressed nodes have variable-sized array */
#define CNODESIZE(nkeys,isleaf)	(sizeof(compnode) + \
			((isleaf) ? (((nkeys)-1)*HASHSIZE) : (2*(nkeys)*HASHSIZE)))


/*
 * Persistent data
 * This data is not sensitive but must be preserved across reboots.
 * hashroot is the hash of the top node of the tree.  Each node contains
 * the hash of its children.  Hence this is in effect a hash of the whole
 * tree.  This is what allows us to validate proper behavior of the
 * untrusted host.  depth is the current depth of the tree, used in the
 * validation algorithm so we know when we get to a leaf node.
 * Btrees have the property that all branches are the same depth, because
 * we only add nodes at the top.
 *
 * We keep this data in both DRAM and BBRAM, which is persistent.
 * We read it from DRAM, and write it to both on every change.
 * After a reboot we read it back from BBRAM into DRAM.
 */
struct dbdata {
	uchar hashroot[HASHSIZE];
	int depth;
};

/*
 * This data structure defines what we put into BBRAM.
 * The actual number of dbdata structs equals nfiles.
 */
struct bbram {
	int nfiles;
	struct dbdata dbdata[1];
} *tdata;


/* Arrays to give room to expand our nodes */
static uchar growkey[NODEKEYS+1][HASHSIZE];
static uchar growchild[NODEKEYS+2][HASHSIZE];


/* Value of hash root on an empty database */
uchar const inithashroot[HASHSIZE] = {
	0x80, 0x41, 0xfd, 0x39, 0xb3, 0xdf, 0xae, 0xda,
	0x50, 0xbb, 0xeb, 0x13, 0xc8, 0xb1, 0x18, 0x30,
	0x26, 0x4a, 0x7b, 0x36
};

/* Name for our persistent data */
static ppd_name_t dbname = {
	'd', 'b', 'd', 'a', 't', 'a', ' ', ' '
};



static int dbvalidate (int *found, void *buf, unsigned long bufsize, uchar *hash, int fileid);
static int newdb_prefix (sccOA_CKO_Name_t *certname, int fileid);


/* Return 0 on successful operation and set *found flag */
int
testdbandset (int *found, sccRequestHeader_t *req, uchar *data,
	unsigned long datalen, int fileid)
{
	long				rc;
	unsigned long		buflen;
	uchar				newhash[SHA1_DIGEST_LENGTH];
	uchar				*buf;
	gbig_sha1ctx		sha1;

	/* Compute the hash of the data */
	gbig_sha1_init (&sha1);
	gbig_sha1_update (&sha1, pdata->prefix+fileid*PREFIXSIZE, PREFIXSIZE);
	gbig_sha1_update (&sha1, data, datalen);
	gbig_sha1_final (newhash, &sha1);

	/* Send hash to the host to be added to the DB */
	/* Also include our hash root (to help resync after crashes) and fileid */
	if ((rc = sccPutBufferData (req->RequestID, 0, newhash, HASHSIZE)) != 0)
		return ERR_FAILEDPUTBUFFER;
	if ((rc = sccPutBufferData (req->RequestID, 1,
				tdata->dbdata[fileid].hashroot, HASHSIZE)) != 0)
		return ERR_FAILEDPUTBUFFER;
	if ((rc = sccEndRequest (req->RequestID, 2, &fileid, sizeof(fileid),
				-ERR_DBQUERY)) != 0)
		return ERR_FAILEDOTHER;

	/* Get response from host */
	if ((rc = sccGetNextHeader(req, 0, SVCWAITFOREVER)) != 0)
	  return ERR_FAILEDOTHER;

	if (req->UserDefined != CMD_DBAUTH)
		return ERR_INVALID;

	/* Read validation data */
	if ((rc = sccGetBufferData (req->RequestID, 0, &buflen,
		sizeof(buflen))) != 0)
		return ERR_FAILEDGETBUFFER;

	if ((buf = malloc(UP4(buflen))) == NULL)
		return ERR_NOMEM;

	if ((rc = sccGetBufferData (req->RequestID, 1, buf, UP4(buflen))) != 0)
		return ERR_FAILEDGETBUFFER;

	/* Check database branch for validity */
	rc = dbvalidate (found, buf, buflen, newhash, fileid);
	free (buf);
	if (rc != 0)
		return rc;
	
	return 0;
}

/* Initialize DB persistent data.  Called when we start up on a fresh card. */
int
initdb ()
{
	long rc;
	int tdatasize = sizeof (tdata->nfiles);

	tdata = malloc (tdatasize);
	tdata->nfiles = 0;
	if ((rc = sccCreate4UpdatePPD (dbname, tdata, tdatasize)) != 0)
		return ERR_FAILEDPPD;
	if (pdata)
		pdata->nprefixes = 0;
	return 0;
}

/*
 * Make sure the fileid we got from the host is OK.
 * Can't be 0-2 as those are our POW files and they get reset
 * periodically.  If it is a new key (i.e. a rollover key)
 * it must be the next sequential key number.  If it is a
 * key from another node, it could be a new key number or it
 * could share an existing fileid.
 */
int
checkdbfileid (int fileid, int newflag)
{
	if (newflag && fileid != tdata->nfiles)
		return ERR_INVALID;
	if (fileid < 3)
		return ERR_INVALID;
	if (fileid > tdata->nfiles)
		return ERR_INVALID;
	return 0;
}

/* Create a new fileid entry corresponding to a new empty DB. */
int
newdb (sccOA_CKO_Name_t *certname, int fileid)
{
	long rc;
	int tdatasize;

	(void) certname;

	if (fileid < 0 || fileid > tdata->nfiles)
		return ERR_INVALID;

	/* Do nothing if not adding a new one */
	if (fileid < tdata->nfiles)
		return 0;

	tdata->nfiles += 1;
	tdatasize = sizeof(tdata->nfiles) +
		tdata->nfiles * sizeof(struct dbdata);
	tdata = realloc (tdata, tdatasize);
	
	memcpy (tdata->dbdata[fileid].hashroot, inithashroot, HASHSIZE);
	tdata->dbdata[fileid].depth = 2;
	if ((rc = sccCreate4UpdatePPD (dbname, tdata, tdatasize)) != 0)
		return ERR_FAILEDPPD;

	/* Add a new random prefix to the persistent sensitive data */
	if ((rc = newdb_prefix (certname, fileid)) != 0)
		return rc;
	return 0;
}


/* Add a new random prefix to the persistent data */
static int
newdb_prefix (sccOA_CKO_Name_t *certname, int fileid)
{
	int pd1;
	int rc;

	pd1 = (pdata == pdata1);
	if (pdata->nprefixes != fileid)
		return ERR_INVALID;
	pdata->nprefixes += 1;
	pdata1 = realloc (pdata1, PDATALEN(pdata));
	pdata2 = realloc (pdata2, PDATALEN(pdata));
	pdata = pd1 ? pdata1 : pdata2;
	gbig_rand_bytes (pdata->prefix+fileid*PREFIXSIZE, PREFIXSIZE);
	if ((rc = savesecrets (certname)) != 0)
		return rc;
	return 0;
}

/* Called when card reboots */
int
rebootdb (sccOA_CKO_Name_t *certname)
{
	long rc;
	unsigned long tdatasize = 0;
	(void) certname;
	/* We are rebooting */
	if ((rc = sccGetPPDLen (dbname, &tdatasize)) != 0)
		return ERR_FAILEDPPD;
	tdata = malloc (tdatasize);
	if ((rc = sccGetPPD (dbname, tdata, tdatasize)) != 0)
		return ERR_FAILEDPPD;
	return 0;
}

/*
 * Call periodically, at least once every two weeks(!)
 * Resets the unused POW DB during the first two weeks of the month
 * We use fileids 0-2 in round robin fashion for the month that a
 * POW was created.  We only accept them for a few days in the past and
 * less in the future.  So if we are in the first part of month 0, for
 * example, we will reset the database for month 1.  This assumes similar
 * actions on the part of the host, that it deletes and resets its POW
 * databases when they are no longer in use.
 */
int
dbresetpow (sccOA_CKO_Name_t *certname)
{
	long rc;
	time_t nowtime = time(NULL);
	struct tm *t = localtime (&nowtime);
	int fileid;
	int tdatasize;

	if (tdata->nfiles >= 3  &&  t->tm_mday < 16)
	{
		/* Get number of next month's POW DB, which is unused */
		fileid = (t->tm_mon+1) % 3;
		if (memcmp (tdata->dbdata[fileid].hashroot, inithashroot, HASHSIZE)
				!= 0)
		{
			memcpy (tdata->dbdata[fileid].hashroot, inithashroot, HASHSIZE);
			tdata->dbdata[fileid].depth = 2;
			tdatasize = sizeof(tdata->nfiles) +
						tdata->nfiles * sizeof(struct dbdata);
			if ((rc = sccCreate4UpdatePPD (dbname, tdata, tdatasize)) != 0)
				return ERR_FAILEDPPD;
			if (pdata->nprefixes >= 3)
			{
				gbig_rand_bytes (pdata->prefix+fileid*PREFIXSIZE, PREFIXSIZE);
				if ((rc = savesecrets (certname)) != 0)
					return rc;
			}
		}
	}
	return 0;
}


/*****************************  VALIDATE  *******************************/


/*

The idea here is that an untrusted system can maintain the DB, and provide
evidence to a second system as to whether any given item is found or not
(and added if missing).  The second system maintains a hash over the
whole DB, following the btree structure.  It checks the returned evidence
data against the hash to make sure it matches, verifies that the evidence
does in fact prove presence or absence, and if adding, independently
calculates the updated hash, using an algorithm that mirrors that done on
the untrusted system.

*/


/* Hash the given node key and childhash data (if nonleaf) and return result */
static void
nodedatahash (uchar *hash, uchar *key, uchar *childhash, int nkeys, int isleaf)
{
#if SHA1_DIGEST_LENGTH > HASHSIZE
	uchar md[SHA1_DIGEST_LENGTH];
#endif
	ulong nnkeys = htonl (nkeys);
	gbig_sha1ctx ctx;

	gbig_sha1_init (&ctx);
	gbig_sha1_update (&ctx, &nnkeys, sizeof(nnkeys));
	gbig_sha1_update (&ctx, key, nkeys*HASHSIZE);
	if (!isleaf)
	{
		gbig_sha1_update (&ctx, childhash, (1+nkeys)*HASHSIZE);
	}
#if SHA1_DIGEST_LENGTH == HASHSIZE
	gbig_sha1_final (hash, &ctx);
#else
	gbig_sha1_final (md, &ctx);
	memcpy (hash, md, HASHSIZE);
#endif
}

/* Return <0, 0, or >0 as key1 is <, ==, or > key2 */
static int
keycomp (uchar *key1, uchar *key2)
{
	int i;
	uchar k1, k2;

	for (i=0; i<HASHSIZE; i++)
	{
		k1 = key1[i];
		k2 = key2[i];
		if (k1 > k2)
			return 1;
		else if (k1 < k2)
			return -1;
	}
	return 0;
}


static int
_validate_db_node (int *found, compnode *node, int nilen, uchar *thisnodehash,
	uchar *newhash, int depth, int maxdepth, int set, int *splitflag,
	uchar *splitkey, uchar *newnodehash)
{
	uchar hash[HASHSIZE];
	uchar *childnodehash;
	compnode *childnode;
	int valid;
	int comp;
	int nkeys;
	int keyind;
	int nodesize;
	int isleaf = (depth+1 == maxdepth);

	/* Pick up values from compnode */
	if (nilen < sizeof(int))
		return 0;
	nkeys = ntohl (node->nkeys);
	if (nkeys < 0 || nkeys > NODEKEYS)
		return 0;
	nodesize = CNODESIZE(nkeys, isleaf);
	if (nilen < nodesize || (isleaf && (nilen != nodesize)))
		return 0;
	keyind = ntohl (node->keyind);
	if (keyind < 0 || keyind > nkeys)
		return 0;

	/* Verify that this node's data matches expected hash */
	nodedatahash (hash, node->hashdata[0], node->hashdata[nkeys],
			nkeys, isleaf);
	if (memcmp (hash, thisnodehash, HASHSIZE) != 0)
		return 0;

	/* Validate that keyind is correct */
	if (keyind < nkeys)
	{
		comp = keycomp (newhash, node->hashdata[keyind]);
		if (comp == 0)
		{
			*found = 1;
			return 1;
		}
		if (comp > 0)
			return 0;
	}
	if (keyind > 0)
	{
		comp = keycomp (newhash, node->hashdata[keyind-1]);
		if (comp <= 0)
			return 0;
	}

	if (isleaf)
	{
		/* Done, unfound, if not inserting */
		if (!set)
		{
			*found = 0;
			return 1;
		}

		/* Leaf node, just add the data */
		memcpy (growkey[0], node->hashdata[0], keyind*HASHSIZE);
		memcpy (growkey[keyind], newhash, HASHSIZE);
		memcpy (growkey[keyind+1], node->hashdata[keyind],
				(nkeys-keyind)*HASHSIZE);
		++nkeys;
	} else {
		/* Recurse */
		*splitflag = 0;
		childnode = (compnode *)((uchar *)node + nodesize);
		childnodehash = node->hashdata[nkeys+keyind];	/* childhash field */
		valid = _validate_db_node (found, childnode, nilen-nodesize,
			childnodehash, newhash, depth+1, maxdepth, set, splitflag,
			splitkey, newnodehash);

		if (!valid)
			return 0;

		if (!set || *found)
			return 1;

		if (*splitflag == 0)
		{
			/* No split below us, just update our changed hash upwards */
			nodedatahash (thisnodehash, node->hashdata[0],
				node->hashdata[nkeys], nkeys, isleaf);
			return 1;
		}

		/* Child did a split, new node is to right of old one */
		memcpy (growkey[0], node->hashdata[0], keyind*HASHSIZE);
		memcpy (growkey[keyind], splitkey, HASHSIZE);
		memcpy (growkey[keyind+1], node->hashdata[keyind],
				(nkeys-keyind)*HASHSIZE);
		memcpy (growchild[0], node->hashdata[nkeys+0], (keyind+1)*HASHSIZE);
		memcpy (growchild[keyind+1], newnodehash, HASHSIZE);
		memcpy (growchild[keyind+2], node->hashdata[nkeys+keyind+1],
					(nkeys-keyind)*HASHSIZE);
		++nkeys;
	}

	/* Now split our node if it is too full */
	/* We move one key up (to splitkey) and put NODEKEYS/2 in this one and */
	/* the new one.  The new node gets the higher value keys and is the */
	/* right sibling of the existing node. */
	if (nkeys > NODEKEYS)
	{
		assert (nkeys == NODEKEYS+1);
		memcpy (splitkey, growkey[NODEKEYS/2], HASHSIZE);
		nkeys = NODEKEYS/2;
		*splitflag = 1;

		/* Now hash the split data into the two parent fields */
		nodedatahash (thisnodehash, growkey[0], growchild[0], nkeys, isleaf);
		nodedatahash (newnodehash, growkey[nkeys+1], growchild[nkeys+1],
				nkeys, isleaf);
	} else {
		/* No split was done, just update parent hash */
		*splitflag = 0;
		nodedatahash (thisnodehash, growkey[0], growchild[0], nkeys, isleaf);
	}

	return 1;
}

/*
 * Return true if valid, false if not.  Return *found as true if we found
 * the data item (if we are returning valid).
 * Update treehash if set is true and not found (and valid).
 */
static int
validate_db_operation (uchar *treehash, int *found, compnode *nodeinfo,
	int nilen, int *maxdepth, uchar *newhash, int set)
{
	int valid;
	int splitflag;
	uchar splitkey[HASHSIZE];
	uchar newnodehash[HASHSIZE];

/*
	First test: that each node either matches newhash on key[keyind] (in which
	case it is found) or else newhash is between key[keyind] and key[keyind+1]
	(or if keyind == nkeys-1 then newhash is above key[keyind]).

	Second test: that hashing each node produces the parent childhash field.

	Third test: that hashing the root node produces our saved treehash.

	Given all these three tests, we validate the presence/absence of the
	item.  If found, or if set is false, we are done.

	Otherwise we have to do updates and ultimately we are updating treehash.
	To do the updates we insert the new node data where it should go, and
	split the node if necessary.

	For recursive testing, first check the tree hash at the top level.
	Then at each level first test the keyind value, then test the childhash
	of the next level (if recursing).  I.e. before recursing check the
	childhash to make sure it is as expected.  Thus we validate each data
	before trusting it.
*/

	*found = 0;
	splitflag = 0;

	valid = _validate_db_node (found, nodeinfo, nilen, treehash, newhash, 0,
		*maxdepth, set, &splitflag, splitkey, newnodehash);

	if (!valid)
		return 0;

	if (!set || *found || (splitflag==0))
		return 1;

	/* Must create new top node because old top filled up and split */
	/* Top node has only one item, the splitkey, and two hashes */
	/* We only need to update the treehash from it */
	memcpy (growchild[0], treehash, HASHSIZE);
	memcpy (growchild[1], newnodehash, HASHSIZE);
	nodedatahash (treehash, splitkey, growchild[0], 1, NONLEAF);
	(*maxdepth)++;

	return 1;
}


static int
dbvalidate (int *found, void *buf, unsigned long bufsize, uchar *hash, int fileid)
{
	long rc;
	int valid;

	valid = validate_db_operation (tdata->dbdata[fileid].hashroot, found,
		(compnode *)buf, bufsize, &tdata->dbdata[fileid].depth, hash, 1);

	if (valid)
	{
		int tdataoff = sizeof (tdata->nfiles) +
				fileid * sizeof (struct dbdata);
		if ((rc = sccUpdatePPD (dbname, &tdata->dbdata[fileid],
				sizeof(struct dbdata), tdataoff)) != 0)
			return ERR_FAILEDPPD;
	}

	if (!valid)
		return ERR_DBFAILED;

	return 0;
}
