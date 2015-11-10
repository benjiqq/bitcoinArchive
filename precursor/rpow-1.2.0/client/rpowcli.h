/*
 * rpowcli.h
 *	Internal header file for reusable proof of work tokens
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

#ifndef RPOWCLI_H
#define RPOWCLI_H

#include "rpow.h"
#include "rpowclient.h"

/* Default file names */
#define RPOWDIR		".rpow"
#define SIGNFILE	"rpowkey.pub"
#define COMMFILE	"commkey.pub"
#define RPOWFILE	"rpows.dat"
#define CONFIGFILE	"config"

#define DEFAULTPORT	4902


/*typedef unsigned long ulong;*/
typedef unsigned char uchar;


/* "Pending" RPOW, one waiting to be signed by the server */
/* rpow is in rpowclient.h */
typedef struct rpowpend {
	gbignum rpow;
	gbignum rpowhidden;
	gbignum invhider;
	int value;
	uchar id[RPOW_ID_LENGTH + CARDID_LENGTH];
	int idlen;
} rpowpend;


/* rpow.c */
/* rpow functions are declared in rpowclient.h */

char * powresource (unsigned char *cardid);
rpowpend *rpowpend_gen (int value, int dohide, pubkey *);
int rpowpend_write (rpowpend *, rpowio *rpio);
rpowpend *rpowpend_read (rpowio *rpio);
rpow * rpowpend_rpow (rpowpend *, pubkey *, rpowio *rpio);
void rpowpend_free (rpowpend *);

int valuetoexp (gbignum *exp, int value, pubkey *pk);

#endif /* RPOWCLI_H */
