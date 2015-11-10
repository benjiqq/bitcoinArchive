/*
 * rpowclient.h
 *	External header file for reusable proof of work tokens
 *
 * Copyright (C) 2004 Hal Finney
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RPOWCLIENT_H
#define RPOWCLIENT_H

#include <openssl/bio.h>

#include "gbignum.h"

#ifndef KEYID_LENGTH
#  define KEYID_LENGTH	20
#endif
#ifndef CARDID_LENGTH
#  define CARDID_LENGTH	14
#endif

/* Public keys, for communication and rpow signature verification */
typedef struct pubkey {
	gbignum n;
	gbignum e;
	unsigned char keyid[KEYID_LENGTH];
#define PUBKEY_STATE_SIGNING	1
#define PUBKEY_STATE_ACTIVE		2
#define PUBKEY_STATE_INACTIVE	3
	int state;
	unsigned char cardid[CARDID_LENGTH];
} pubkey;


/* Reusable proof of work */
typedef struct rpow {
	unsigned char type;
	int value;
	gbignum bn;
	unsigned char keyid[KEYID_LENGTH];
	unsigned char *id;
	int idlen;
} rpow;

/* Generic I/O channel representative */
typedef struct rpowio {
	FILE *f;
	BIO *bio;
} rpowio;


/* File names for keys */
extern char *rpowfile;
extern char *signfile;
extern char *commfile;

/* Host and port for server */
extern char targethost[256];
extern int targetport;

/* Optional SOCKS V5 host and port */
extern int usesocks;
extern char sockshost[256];
extern int socksport;


/* rpowclient.c */

int server_exchange (rpow **rpout, char *target, int port, int nin, rpow **rpin,
	int nout, int *outvals, pubkey *signkey);
void initfilenames (void);

/* connio.c */

int getkeys (char *target, int port, int firsttime);
int getstat (char *target, int port, FILE *fout);
int comm4758 (BIO *bio, char *target, int port, pubkey *signkey);

/* rpio.c */

rpowio *rp_new_from_file (FILE *f);
rpowio *rp_new_from_bio (BIO *bio);
rpowio *rp_new_from_buf (unsigned char *buf, unsigned buflen);
void rp_free (rpowio *);
int rp_write (rpowio *, void *, unsigned);
int rp_read (rpowio *, void *, unsigned);

int bnread( gbignum *bn, rpowio *rpio );
int bnwrite( gbignum *bn, rpowio *rpio );


/* keys.c */

void pubkey_read (pubkey *key, char *file);
void pubkey_write (pubkey *key, char *file);

/* rpowutil.c */

rpow *rpow_gen (int value, unsigned char *cardid);
int rpow_write(rpow *, rpowio *);
rpow *rpow_read (rpowio *rpio);
void rpow_free (rpow *);
rpow *rpow_from_string (char *str);
rpow *rpow_from_buf (unsigned *bytesused, unsigned char *buf, unsigned inlen);
unsigned char *rpow_to_buf (unsigned *outlen, rpow *rp);
char *rpow_to_string (rpow *rp);
rpow * rpow_from_store (int value);
int rpow_to_store (rpow *rp);
int rpow_count (int counts[]);

unsigned char * hc_to_buffer (char *buf, int *pbuflen);

#endif /* RPOWCLIENT_H */
