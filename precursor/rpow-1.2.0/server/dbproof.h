#ifndef DBPROOF_H
#define DBPROOF_H

/*
 * dbproof.h
 *	Maintain database for remote host in a provable way
 */

struct dbproof;

typedef struct dbproof dbproof;

/* The database holds values of size HASHSIZE */
#define HASHSIZE	20

/*
 * Return 1 if present, 0 if was absent.  If set is true, add it if absent.
 * Return *proof and *prooflen as a buffer that proves our correct operation,
 * suitable for presenting to the remote host where a verification algorithm
 * can confirm that we are operating properly.
 */
int testdbandmaybeset (dbproof *db, unsigned char **proof, unsigned *prooflen,
	unsigned char *hash, int set);

#define testdbandset(db,p,pl,h)		testdbandmaybeset(db,p,pl,h,1)
#define testdb(db,p,pl,h)			testdbandmaybeset(db,p,pl,h,0)

/* Return the depth of the DB btree */
int testdb_depth (dbproof *db);

/*
 * Locally test the validity proof; the exact same algorithm should be
 * used by the remote host.
 */
void testvalid (void *proof, unsigned prooflen, unsigned char *treehash,
		int *maxdepth, unsigned char *hash, int shouldbefound, int set);

/*
 * Open the database file of the specified name.
 * Create it if it doesn't exist.
 * Another file with extension .vals added is also used.
 */
dbproof * opendb (char *name, int *created);

void freedb (dbproof *db);

#endif /* DBPROOF_H */
