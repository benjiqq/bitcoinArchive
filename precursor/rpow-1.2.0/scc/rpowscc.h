/*
 * rpowscc.h
 *	Header file for SCC code of RPOW
 */

#ifndef SECSCC_H
#define SECSCC_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stduser.h>
#include <time.h>
#include <scctypes.h>
#include <scc_int.h>
#include <scc_oa.h>
#include <qsvccnst.h>
#include <cpqlib.h>
#include <rslbswap.h>
#include "rpow.h"
#include "gbignum.h"
#include "hmac.h"
#include "cryptchan.h"

#define ntohl        rswapl
#define htonl        rswapl
#define ntohs        rswaps
#define htons        rswaps

/* Prefix used for hashing data we store in database */
#define PREFIXSIZE		SHA1_DIGEST_LENGTH

/* Hash size for data we store in database */
#define HASHSIZE		SHA1_DIGEST_LENGTH


typedef struct rpowio {
	unsigned char	*buf;
	unsigned		len;
	unsigned		off;
} rpowio;

typedef struct pubkey {
	gbignum n;
	gbignum e;
	unsigned char keyid[KEYID_LENGTH];
#define PUBKEY_STATE_SIGNING	1
#define PUBKEY_STATE_ACTIVE		2
#define PUBKEY_STATE_INACTIVE	3
	int state;
	int fileid;
} pubkey;

/* Reusable proof of work */
typedef struct rpow {
	unsigned char type;
	int value;
	gbignum bn;
	unsigned char keyid[KEYID_LENGTH];
	unsigned int fileid;
	unsigned char *id;
	int idlen;
} rpow;

/* "Pending" RPOW, one waiting to be signed by the server */
typedef struct rpowpend {
	gbignum rpow;
	int value;
} rpowpend;

/* rpio.c */
rpowio * rp_new (void);
rpowio * rp_new_from_buf (unsigned char *buf, unsigned len);
rpowio * rp_new_from_malloc_buf (unsigned char *buf, unsigned len);
unsigned char *rp_buf (rpowio *rp, unsigned *len);
void rp_free (rpowio *rp);
int rp_write (rpowio *rp, void *buf, unsigned len);
int rp_read (rpowio *rp, void *buf, unsigned len);
int bnwrite (gbignum *bn, rpowio *rpio);
int bnread (gbignum *bn, rpowio *rpio);
int pubkey_read (pubkey *pk, rpowio *rpio);
int pubkey_write (pubkey *pk, rpowio *rpio);

/* keygen.c */

/*
 * Persistent data.
 * This data is sensitive but hardly ever changes.
 * We store it in flash rom, encrypted with the OA key.
 * The tdkey is used to encrypt our rpow signature data we store in
 * flash.
 */
struct rpowdata {
	unsigned char rsaprefix[2];
	unsigned char tdkey[TDESKEYBYTES];
	unsigned char pad[MAXRSAKEYBYTES-(2+TDESKEYBYTES)];
} sdata;

/*
 * We store persistent data encrypted in flash, and also two copies in
 * DRAM memory.  One copy is xored with FF's.  Every so often we switch
 * copies.  This is hoped to prevent memory burn-in.
 */
extern struct persistdata {
	sccRSAKeyToken_t		commkey;
	unsigned char			commkeydata[10*MAXRSAKEYBYTES];
	unsigned long			commkeylen;

	sccRSAKeyToken_t		rpowkey;
	unsigned char			rpowkeydata[10*MAXRSAKEYBYTES];
	unsigned long			rpowkeylen;
	unsigned char			rpowdpq[2*RPOW_VALUE_COUNT*MAXRSAKEYBYTES/2];

	unsigned long			nprefixes;
	unsigned char			prefix[PREFIXSIZE];		/* actually nprefixes*PREFIXSIZE */
} *pdata1, *pdata2, *pdata;

#define UP8(x)				((((x)+7)/8)*8)
#define PDATALEN(p)			UP8(sizeof(struct persistdata) + ((p)->nprefixes-1)*PREFIXSIZE)

extern unsigned char	rpowblind[RPOW_VALUE_COUNT*2*MAXRSAKEYBYTES];

/* Pubkey version of our signing key, includes our signing keyid */
extern pubkey			rpowsignpk;

/* Card ID is unique among all cards; taken from AdapterInfo_t structure */
extern unsigned char	cardid[CARDID_LENGTH];

/* Our hashcash resource string, based on cardid, null terminated */
extern char powresource[];

/* Flag values for dokeygen */
#define KEYGEN_ROLL		0
#define KEYGEN_NEW		1
int dokeygen (sccOA_CKO_Name_t *certname, int size, int fileid, int newflag);
int getcertchain (unsigned char **pcertbuf, unsigned long *pcertbuflen,
	sccOA_CKO_Name_t *certname);
int dochain (sccRequestHeader_t *req, sccOA_CKO_Name_t *certname, int bufidx);
void setrpowsignpk (sccRSAKeyToken_t *key);
void blindgenall (void);

/* rpowsign.c */
int dosign (sccRequestHeader_t *req, sccOA_CKO_Name_t *certname,
		sccRSAKeyToken_t *commkey, unsigned long commkeylen,
		sccRSAKeyToken_t *key, unsigned long keylen);

/* rpowutil.c */
int issmallprime (int x);
int valuetoexp (gbignum *exp, int value, pubkey *pk);
rpow * rpow_read (rpowio *rpio);
int rpow_write (rpow *rp, rpowio *rpio);
void rpow_free (rpow *rp);
rpowpend * rpowpend_read (rpowio *rpio);
int rpowpend_write (rpowpend *rpend, rpowio *rpio);
void rpowpend_free (rpowpend *rpend);
int rpow_validate (rpow *rp);

/* persist.c */
void pk_to_keyid (pubkey *key);
int rebootpubkeys (sccOA_CKO_Name_t *certname);
int initpubkeys (void);
int addpubkey (gbignum *n, int fileid, int status);
int doaddkey (sccRequestHeader_t *req, sccOA_CKO_Name_t *certname);
int dochangekeystate (sccRequestHeader_t *req, sccOA_CKO_Name_t *certname);
int setcardid (sccOA_CKO_Name_t *certname);
pubkey * pk_from_keyid (unsigned char *keyid);
pubkey * pk_from_index (int i);
int savesecrets (sccOA_CKO_Name_t *certname);
int rebootsecrets (sccOA_CKO_Name_t *certname);
void swappdata (void);

/* dbverify.c */
int initdb (void);
int newdb (sccOA_CKO_Name_t *certname, int fileid);
int checkdbfileid (int fileid, int newflag);
int rebootdb (sccOA_CKO_Name_t *certname);
int dbresetpow (sccOA_CKO_Name_t *certname);
int testdbandset (int *found, sccRequestHeader_t *req, unsigned char *data,
	unsigned long datalen, int fileid);

/* certvalid.c */
int certvalidate ( unsigned char **innerbuf, unsigned long *innerbuflen,
	unsigned char *certbuf, unsigned long certbuflen, sccOA_CKO_Name_t *certname);

#endif
