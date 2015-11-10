/*
 * dbproof.c
 *	Maintain a database of used items on behalf of a remote host,
 *  proving correctness of operations to that host even though it
 *	does not have the ability to remember more than a few bytes about
 *	the whole database.
 */


#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#if !defined(_WIN32)
#include <unistd.h>
#include <sys/file.h>
#include <sys/time.h>
#endif
#include "dbproof.h"
#include "sha.h"

#if defined(_WIN32)
typedef unsigned off_t;
typedef unsigned ssize_t;
#define ntohl(x) ((((x)>>24)&0xff)|(((x)>>8)&0xff00)| \
					(((x)&0xff00)<<8)|(((x)&0xff)<<24))
#define htonl	ntohl
#endif

/*

Now we are going to use M-ary trees rather than binary.
We are also going to take out locking; our current architecture will
be basically single threaded, and if we support multiple servers each
will have its own spent list(s).

This will use true B-trees.  Each node will have between NODEKEYS/2 and
NODEKEYS keys, except the top node which may have fewer.  Also we will
possibly change the top node.

Clean up use of multiple files, one for inner nodes and one for bottom
nodes.  Eliminate our hash prefix, not necessary with btrees.

Add evidence field (nodinfo) for use in proving to a third party that the
DB is being maintained consistently.

*/

/* Number of keys per node, must be even */
#define NODEKEYS	100

#define MAXDEPTH	6

#define NONLEAF		0
#define ISLEAF		1

#define INODESIZE	(sizeof(innernode))
#define LNODESIZE	(sizeof(leafnode))

/* Compressed nodes have variable-sized array */
#define CNODESIZE(nkeys,isleaf)	(sizeof(compnode) + \
			((isleaf) ? (((nkeys)-1)*HASHSIZE) : (2*(nkeys)*HASHSIZE)))


#if defined(_WIN32)
typedef unsigned long ulong;
#endif
typedef unsigned char uchar;

/* We allow NODEKEYS+1 keys in a node temporarily but will split it */
typedef struct innernode {
									/* leafnode must prefix innernode */
	ulong nkeys;					/* Number of keys in node */
	uchar key[NODEKEYS+1][HASHSIZE];	/* Keys are kept sorted */
	uchar childhash[NODEKEYS+2][HASHSIZE];
	ulong child[NODEKEYS+2];		/* Node number in file of children */
} innernode;

typedef struct leafnode {
	ulong nkeys;					/* Number of keys in node */
	uchar key[NODEKEYS+1][HASHSIZE];	/* Keys are kept sorted */
} leafnode;

/* Compressed nodes are what are put into the nodeinfo array */
typedef struct compnode {
	ulong nkeys;
	ulong keyind;
	uchar hashdata[1][HASHSIZE];	/* Actually 2*nkeys+1 hashes */
									/* First, nkeys key hashes, then */
									/* if non-leaf, nkeys+1 childhashes */
} compnode;


struct dbproof {
	int fdi;		/* inner nodes */
	int fdl;		/* leaf nodes */
	int depth;		/* Depth of tree */
	int rootnode;	/* Root node number in fdi file */
	innernode newnode;	/* Used and re-used for adding nodes to the tree */
						/* Remainder is used for proof of validity */
	uchar nodeinfo[CNODESIZE(NODEKEYS,NONLEAF) * MAXDEPTH];
	compnode *nodeptr;
	uchar treehash[HASHSIZE];	/* for testing */
	int treedepth;				/* for testing */
};

static void nodehash (uchar *hash, innernode *n, int nkeys, int isleaf);
static int _testdbandmaybeset_node (dbproof *db, int nodepos,
	uchar *thisnodehash, uchar *newhash, int set, int depth,
	int *pnewnodenum, uchar *splitkey, uchar *newnodehash);

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

/*
 * See if a key is in a node.  Return true if it is, and set *keyind to the
 * index number of the key (0 to NODEKEYS-1).  Return false if it is not,
 * and set *keyind to the index number of the space between the keys where
 * it would go (0 to NODEKEYS).
 */
static int
nodefindkey (leafnode *n, uchar *key, int *keyind)
{
	int i;
	int m, l, h;
	int comp;
	int nkeys = ntohl (n->nkeys);

	/* Binary search */
	l = 0; h = nkeys-1;
	i = 0;
	while (l <= h)
	{
		m = (l+h)/2;
		comp = keycomp (n->key[m], key);
		if (comp == 0)
		{
			*keyind = m;
			return 1;
		} else if (comp > 0) {
			h = m-1;
		} else {
			l = m+1;
			if (m+1 > i)
				i = m+1;
		}
	}
	*keyind = i;
	return 0;
}


/* Functions to seek to, read from and write to a node */

static off_t
dbnodeseek (dbproof *db, off_t off, int whence, int isleaf)
{
	off_t err;

	if (isleaf)
		err = lseek (db->fdl, off*LNODESIZE, whence);
	else
		err = lseek (db->fdi, off*INODESIZE, whence);
	if (err < 0)
		return err;
	return err / (isleaf ? LNODESIZE : INODESIZE);
}

static ssize_t
dbnoderead (dbproof *db, innernode *n, int isleaf)
{
	ssize_t err;

	if (isleaf)
		err = read (db->fdl, n, LNODESIZE);
	else
		err = read (db->fdi, n, INODESIZE);
	if (err < 0)
		return err;
	return err / (isleaf ? LNODESIZE : INODESIZE);
}

static ssize_t
dbnodewrite (dbproof *db, innernode *n, int isleaf)
{
	ssize_t err;

	if (isleaf)
		err = write (db->fdl, n, LNODESIZE);
	else
		err = write (db->fdi, n, INODESIZE);
	if (err < 0)
		return err;
	return err / (isleaf ? LNODESIZE : INODESIZE);
}


#if PROFILE
/* Debugging */
/* Was having some weird timing problems when rapidly filling the db */
static struct timeval pt;
static void
ttime (struct timeval *tm, char *msg)
{
	struct timeval ct;

	gettimeofday (&ct, NULL);
	tm->tv_usec = ct.tv_usec - tm->tv_usec;
	tm->tv_sec = ct.tv_sec - tm->tv_sec;
	if (tm->tv_usec < 0)
	{
		tm->tv_usec += 1000000;
		tm->tv_sec -= 1;
	}
	if (tm->tv_sec > 2)
		printf ("Took %d.%03d seconds: %s\n", tm->tv_sec, tm->tv_usec/1000,msg);
	*tm = ct;
}
#else
#define ttime(a,b)
#endif

/*
 * Return 1 if present, 0 if was absent.  If set is true, add it if absent.
 * Also return *proof and *prooflen as a buffer (within proofdb) which proves
 * our correctness.
 */
int
testdbandmaybeset (dbproof *db, unsigned char **proof, unsigned *prooflen,
	unsigned char *hash, int set)
{
	innernode n;
	uchar splitkey[HASHSIZE];
	uchar newnodehash[HASHSIZE];
	uchar treehash[HASHSIZE];
	int found;
	int newnodenum;
	int newtopnodenum;

#if PROFILE
timerclear(&pt);
gettimeofday(&pt,NULL);
#endif

	/* Set things up for validity proof */
	db->treedepth = db->depth;
	db->nodeptr = (compnode *)db->nodeinfo;

	/* Do the recursive search */
	found = _testdbandmaybeset_node (db, db->rootnode, treehash, hash, set,
			0, &newnodenum, splitkey, newnodehash);
	if (!set || found || (newnodenum==0))
	{
		if (proof)
			*proof = db->nodeinfo;
		if (prooflen)
			*prooflen = (uchar *)db->nodeptr - db->nodeinfo;
printf ("New DB root hash:         "); dumpbuf (treehash, HASHSIZE);
		return found;
	}

	/* Must create new top node because old top filled up and split */
	memset (&db->newnode, 0, INODESIZE);
	memcpy (db->newnode.key[0], splitkey, HASHSIZE);
	db->newnode.nkeys = htonl(1);
	db->newnode.child[0] = htonl (db->rootnode);
	db->newnode.child[1] = htonl (newnodenum);
	memcpy (db->newnode.childhash[0], treehash, HASHSIZE);
	memcpy (db->newnode.childhash[1], newnodehash, HASHSIZE);
	++db->depth;
	assert (db->depth <= MAXDEPTH);
printf ("Splitting top node, increasing DB depth to %d\n", db->depth);

	/* Write out new top node */
	newtopnodenum = dbnodeseek (db, 0, SEEK_END, NONLEAF);
ttime(&pt, "seek to end");
	dbnodewrite (db, &db->newnode, NONLEAF);
ttime(&pt, "write new node");

	/* Put its position in block 0 */
	n.child[0] = htonl (newtopnodenum);
	n.child[1] = htonl (db->depth);
	dbnodeseek (db, 0, SEEK_SET, NONLEAF);
	dbnodewrite (db, &n, NONLEAF);

	db->rootnode = newtopnodenum;

	if (proof)
		*proof = db->nodeinfo;
	if (prooflen)
		*prooflen = (uchar *)db->nodeptr - db->nodeinfo;

	return 0;
}

/*
 * Search the tree starting at the node with number nodepos.  Return 1
 * if newhash is found, 0 if it was not found.  If it was not found and
 * set is true, insert it in the tree.  Insertion may require node
 * splitting.  If that happens, we set *pnewnodenum to the number of the
 * new node (which will be the right sibling of the existing node).
 * We set splitkey to be the key at which we split, the middle key, which
 * is supposed to move up into the parent node.  And we set newnodehash
 * to be the hash of the new node.  Also if we made a change to the
 * existing node, we set thisnodehash to the new hash of the node.
 */
static int
_testdbandmaybeset_node (dbproof *db, int nodepos, uchar *thisnodehash, 
	uchar *newhash, int set, int depth, int *pnewnodenum, uchar *splitkey,
	uchar *newnodehash)
{
	innernode n;
	int childpos;
	int keyind;
	int nkeys;
	int found;
	int isleaf = (depth+1 == db->depth);

	dbnodeseek (db, nodepos, SEEK_SET, isleaf);
ttime(&pt, "first lseek");
	dbnoderead (db, &n, isleaf);
ttime(&pt, "first read");

	nkeys = ntohl(n.nkeys);
	found = nodefindkey ((leafnode *)&n, newhash, &keyind);

	/* Save data in nodeinfo chain for later proof of correctness */
	db->nodeptr->nkeys = htonl(nkeys);
	db->nodeptr->keyind = htonl(keyind);
	memcpy (db->nodeptr->hashdata[0], n.key[0], nkeys*HASHSIZE);
	if (!isleaf)
	{
		memcpy (db->nodeptr->hashdata[nkeys], n.childhash[0],
					(nkeys+1)*HASHSIZE);
	}
	db->nodeptr = (compnode *)((uchar *)db->nodeptr + CNODESIZE(nkeys,isleaf));

	if (found)
	{
		return 1;
	}

	if (isleaf)
	{
		/* Done, unfound, if not inserting */
		if (!set)
			return 0;

		/* Leaf node, just add data */
		memmove (n.key[keyind+1], n.key[keyind], (nkeys-keyind)*HASHSIZE);
		memcpy (n.key[keyind], newhash, HASHSIZE);
		++nkeys;
	} else {
		/* Traverse the tree */
		childpos = ntohl (n.child[keyind]);
		assert (childpos != 0);
		*pnewnodenum = 0;
		found = _testdbandmaybeset_node (db, childpos, n.childhash[keyind],
			newhash, set, depth+1, pnewnodenum, splitkey, newnodehash);

		if (!set || found)
			return found;

		if (*pnewnodenum == 0)
		{
			/* No split below us, just write out with our updated hash */
			dbnodeseek (db, nodepos, SEEK_SET, isleaf);
	ttime(&pt, "lseek for hash propagate");
			dbnodewrite (db, &n, isleaf);
	ttime(&pt, "write for hash propagate");

			/* And update our parent's hash */
			nodehash (thisnodehash, &n, nkeys, isleaf);
			return 0;
		}

		/* Child did a split, newnode is to the right of the old one */
		memmove (n.key[keyind+1], n.key[keyind], (nkeys-keyind)*HASHSIZE);
		memcpy (n.key[keyind], splitkey, HASHSIZE);
		memmove (n.childhash[keyind+2], n.childhash[keyind+1],
				(nkeys-keyind)*HASHSIZE);
		memcpy (n.childhash[keyind+1], newnodehash, HASHSIZE);
		memmove (n.child+keyind+2, n.child+keyind+1,
				(nkeys-keyind)*sizeof(n.child[0]));
		n.child[keyind+1] = htonl(*pnewnodenum);
		++nkeys;
	}

	/* Now split our node if it is too full */
	/* We move one key up (to splitkey) and put NODEKEYS/2 in this one and */
	/* the new one.  The new node gets the higher value keys and is the */
	/* right sibling of the existing node. */
	if (nkeys > NODEKEYS)
	{
		assert (nkeys == NODEKEYS+1);
		memset (&db->newnode, 0, INODESIZE);
		memcpy (splitkey, n.key[NODEKEYS/2], HASHSIZE);
		memcpy (db->newnode.key[0], n.key[NODEKEYS/2+1], (NODEKEYS/2)*HASHSIZE);
		memset (n.key[NODEKEYS/2], 0, (NODEKEYS/2+1)*HASHSIZE);
		if (!isleaf)
		{
			memcpy (db->newnode.childhash[0], n.childhash[NODEKEYS/2+1],
				(NODEKEYS/2+1) * HASHSIZE);
			memcpy (db->newnode.child, n.child+NODEKEYS/2+1,
				(NODEKEYS/2+1) * sizeof(n.child[0]));
			memset (n.childhash[NODEKEYS/2+1], 0, (NODEKEYS/2+1)*HASHSIZE);
			memset (n.child+NODEKEYS/2+1, 0,
				(NODEKEYS/2+1)*sizeof(n.child[0]));
		}
		db->newnode.nkeys = n.nkeys = htonl(NODEKEYS/2);

		/* Write the old node first, then the new one */
		dbnodeseek (db, nodepos, SEEK_SET, isleaf);
ttime(&pt, "lseek for rewrite");
		dbnodewrite (db, &n, isleaf);
ttime(&pt, "rewrite");
		*pnewnodenum = dbnodeseek (db, 0, SEEK_END, isleaf);
ttime(&pt, "seek to end");
		dbnodewrite (db, &db->newnode, isleaf);
ttime(&pt, "write new node");

		/* And update parent's hashes */
		nodehash (thisnodehash, &n, NODEKEYS/2, isleaf);
		nodehash (newnodehash, &db->newnode, NODEKEYS/2, isleaf);
	}
	else
	{
		/* No split needed, just write the old node */
		*pnewnodenum = 0;		/* Flag that no splits were done here */
		n.nkeys = htonl(nkeys);
		dbnodeseek (db, nodepos, SEEK_SET, isleaf);
ttime(&pt, "lseek for rewrite");
		dbnodewrite (db, &n, isleaf);
ttime(&pt, "rewrite");

		/* And update parent hash */
		nodehash (thisnodehash, &n, nkeys, isleaf);
	}

	return 0;
}


/* Hash the given node key and childhash data (if nonleaf) and return result */
static void
nodedatahash (uchar *hash, uchar *key, uchar *childhash, int nkeys, int isleaf)
{
	uchar md[SHA1_DIGEST_LENGTH];
	ulong nnkeys = htonl (nkeys);
	SHA_CTX ctx;

	SHA1_Init (&ctx);
	SHA1_Update (&ctx, (unsigned char *)&nnkeys, sizeof(nnkeys));
	SHA1_Update (&ctx, key, nkeys*HASHSIZE);
	if (!isleaf)
		SHA1_Update (&ctx, childhash, (1+nkeys)*HASHSIZE);
	SHA1_Final (md, &ctx);
	memcpy (hash, md, HASHSIZE);
}

/* Compute 128 bit hash of node keys and their subtrees */
static void
nodehash (uchar *hash, innernode *n, int nkeys, int isleaf)
{
	nodedatahash (hash, n->key[0], n->childhash[0], nkeys, isleaf);
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


/* Arrays to give room to expand our nodes */
static uchar growkey[NODEKEYS+1][HASHSIZE];
static uchar growchild[NODEKEYS+2][HASHSIZE];

/*
 * Return true if valid, false if not.  Return *found as true if we found
 * the data item (if we are returning valid).
 * Update treehash if set is true and not found (and valid).
 */
int
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

	++(*maxdepth);

	return 1;
}

int
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
 * Local test of the validity verification.
 * Resets treehash and maxdepth just as the remote host should.
 */
void
testvalid (void *proof, unsigned prooflen, uchar *treehash,
		int *maxdepth, uchar *hash, int shouldbefound, int set)
{
	int valid;
	int found;

	valid = validate_db_operation (treehash, &found,
		(compnode *)proof, prooflen, maxdepth, hash, set);

	if (!valid)
	{
		fprintf (stderr, "Invalid validation\n");
		exit (1);
	}
	if (found != shouldbefound)
	{
		fprintf (stderr, "Invalid foundness\n");
		exit (1);
	}
}




/*****************************  DEBUG  *******************************/

/* For debugging */
static void
printnode (dbproof *db, int num, FILE *f, int depth)
{
	innernode n;
	int i, j;
	int isleaf = (depth+1 == db->depth);

	memset (&n, 0, INODESIZE);
	dbnodeseek (db, num, SEEK_SET, isleaf);
	dbnoderead (db, &n, isleaf);
	if (depth+1 == db->depth)
	for (i=0; i<NODEKEYS; i++)
	{
		if (!isleaf)
			printnode (db, ntohl(n.child[i]), f, depth+1);
//		for (j=0; j<depth; j++)
//			fprintf (f, " ");
		for (j=0; j<HASHSIZE; j++)
			fprintf (f, "%02x ", n.key[i][j]);
		fprintf (f, "\n");
	}
	if (!isleaf)
		printnode (db, ntohl(n.child[i]), f, depth+1);
}

void
printdb (dbproof *db, FILE *f)
{
	innernode n;
	uchar hash[HASHSIZE];
	int rootpos;

	dbnodeseek (db, 0, SEEK_SET, NONLEAF);
	dbnoderead (db, &n, NONLEAF);
	rootpos = ntohl (n.child[0]);
	db->depth = ntohl (n.child[1]);
	printnode (db, rootpos, f, 0);
}

static int
checknode (dbproof *db, uchar *hash, int nodenum, int depth)
{
	innernode n;
	int i;
	int isleaf = (depth+1 == db->depth);

	memset (&n, 0, INODESIZE);
	dbnodeseek (db, nodenum, SEEK_SET, isleaf);
	dbnoderead (db, &n, isleaf);

	for (i=0; i<=ntohl(n.nkeys); i++)
	{
		if (!isleaf)
		{
			if (n.child[i] == 0)
				return -1;
			if (checknode (db, hash, ntohl(n.child[i]), depth+1) < 0)
				return -1;
			if (memcmp (hash, n.childhash[i], HASHSIZE) != 0)
				return -1;
		}
		if (i < ntohl(n.nkeys)-1)
			if (keycomp (n.key[i], n.key[i+1]) >= 0)
				return -1;
	}

	nodehash (hash, &n, ntohl(n.nkeys), isleaf);
	return 0;
}

int
checkdb (dbproof *db)
{
	innernode n;
	uchar hash[HASHSIZE];
	int rootpos;

	dbnodeseek (db, 0, SEEK_SET, NONLEAF);
	dbnoderead (db, &n, NONLEAF);
	rootpos = ntohl (n.child[0]);
	db->depth = ntohl (n.child[1]);
	return checknode (db, hash, rootpos, 0);
}

int
testdb_depth (dbproof *db)
{
	return db->depth;
}


/*****************************  INIT  *******************************/


static void
initdb (dbproof *db)
{
	innernode ni;
	leafnode nl;

	/* First leaf node block is unused */
	memset (&nl, 0, LNODESIZE);
	dbnodewrite (db, (innernode *)&nl, ISLEAF);
	/* First leaf node starts off empty */
	dbnodewrite (db, (innernode *)&nl, ISLEAF);

	/* Top inner node just points at root inner node */
	/* And encodes depth in child[1] */
	memset (&ni, 0, INODESIZE);
	ni.child[0] = htonl (1);
	ni.child[1] = htonl (2);
	dbnodewrite (db, &ni, NONLEAF);
	/* Root node will start pointing at leaf */
	memset (&ni, 0, INODESIZE);
	ni.child[0] = htonl (1);
	nodehash (ni.childhash[0], (innernode *)&nl, 0, ISLEAF);
	dbnodewrite (db, &ni, NONLEAF);

	/* Set top level hash for testing validation */
	nodehash (db->treehash, &ni, 0, NONLEAF);

	db->depth = 2;
	db->rootnode = 1;
}

/*
 * Open the database file of the specified name.
 * Create it if it doesn't exist.
 */
dbproof *
opendb (char *name, int *created)
{
	dbproof *db = (dbproof *)malloc (sizeof (dbproof));
	char *leafname = (char *)malloc (strlen(name) + 10);
	int flags = O_RDWR;

#if defined(_WIN32)
	flags |= O_BINARY;
#endif

	strcpy (leafname, name);
	strcat (leafname, ".vals");

	if ((db->fdi = open (name, flags, 0)) >= 0 &&
		(db->fdl = open (leafname, flags, 0)) >= 0)
	{
		innernode n;
		free (leafname);
		/* First entry is dummy and just holds top node pointer and depth */
		dbnodeseek (db, 0, SEEK_SET, NONLEAF);
		dbnoderead (db, &n, NONLEAF);
		db->rootnode = ntohl(n.child[0]);
		db->depth = ntohl(n.child[1]);
		if (created)
			*created = 0;
		return db;
	}
	/* Failed to open DB, try creating it */
	flags |= O_CREAT;
	if ((db->fdi = open (name, flags, 0666)) < 0 ||
		(db->fdl = open (leafname, flags, 0666)) < 0)
	{
		close (db->fdi);
		close (db->fdl);
		free (leafname);
		free (db);
		return NULL;
	}
	initdb(db);
	free (leafname);
	if (created)
		*created = 1;
	return db;
}

void
freedb (dbproof *db)
{
	close (db->fdl);
	close (db->fdi);
	free (db);
}
