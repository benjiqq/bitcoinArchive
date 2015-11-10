/*
 * cryptchan.h
 *	Header file for SCC side of secure crypto channel
 */

#ifndef CRYPTCHAN_H
#define CRYPTCHAN_H

#include <stdlib.h>
#include <stduser.h>
#include <scctypes.h>
#include <scc_int.h>
#include <scc_oa.h>
#include <rslbswap.h>
#include "hmac.h"
#include "errors.h"

#define TDESBYTES		8
#define TDESKEYBYTES	24
#define MAXRSAKEYBYTES	128
#define MAXRSAKEYBITS	(8*MAXRSAKEYBYTES)
#define SEQNOBYTES		8

/* Limit our input size to guard against memory exhaustion */
#define MAXINPUTLEN		10000

struct encstate {
	unsigned char tdeskeyin[TDESKEYBYTES];
	unsigned char tdeskeyout[TDESKEYBYTES];
	unsigned char hmackeyin[SHABYTES];
	unsigned char hmackeyout[SHABYTES];
	unsigned char seqnoin[SEQNOBYTES];
	unsigned char seqnoout[SEQNOBYTES];
	int failed;
};


int keyfromcert (sccRSAKeyToken_t **pkey, unsigned long *pkeylen,
	sccOA_CKO_Name_t *certname);
int decryptmaster (struct encstate *encdata, sccRequestHeader_t *req,
		sccRSAKeyToken_t *key, unsigned long keylen, int bufidx);
int encryptoutput (struct encstate *encdata, unsigned char *buf, unsigned long buflen,
		sccRequestHeader_t *req, int bufidx);
int decryptinput (unsigned char **buf, unsigned long *buflen, struct encstate *encdata,
		sccRequestHeader_t *req, int bufidx);
int tdesdecrypt (unsigned char *obuf, unsigned char *key, unsigned char *ibuf,
	unsigned long buflen);
int tdesencrypt (unsigned char *obuf, unsigned char *key, unsigned char *ibuf,
	unsigned long buflen);

#endif
