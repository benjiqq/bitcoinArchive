/*
 * connio.c
 *	Manage connection I/O for RPOW client package
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

#if defined(_WIN32)
#include <windows.h>
#include <winsock.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/buffer.h>
#include "rpowcli.h"
#include "scc.h"
#include "cryptchan.h"
#include "certvalid.h"
#include "util4758.h"

#if defined(_WIN32)
WSADATA ws;
#define ntohl(x) ((((x)>>24)&0xff)|(((x)>>8)&0xff00)| \
					(((x)&0xff00)<<8)|(((x)&0xff)<<24))
#define htonl	ntohl
#define close	closesocket
#else
typedef int SOCKET;
#endif


/* Maximum size we allow for a cert chain */
#define CHAINSIZE	20000

static unsigned char bigbuf[CHAINSIZE];

/*
 * sha1sum's of the seg 1 ("miniboot", analogous to the bios),
 * seg 2 (OS), and seg 3 (application) that we accept as valid.
 * The application can be verified by (re)constructing the .rod
 * file (memory image) and computing the sha1sum of that file.
 * The OS and miniboot data were found by loading the current
 * versions into the card and seeing what hash it reports.
 */

/* Maximum number of alternative hashes for each level */
#define MAXHASH		2

struct okhash {
	int nhash;
	unsigned char hash[MAXHASH][20];	/* actually 20 by nhash long */
};

struct okhash seg1okhash = {1, 
	/* Version 2.31-2.41 of the 4758 miniboot, "2.41 POST1, MB1" */
	0x1b, 0xdf, 0x67, 0x5f, 0xf8, 0xc5, 0xb3, 0x8d,
	0x57, 0x4d, 0xea, 0xb7, 0x45, 0x42, 0x45, 0x23,
	0xf9, 0xa9, 0xbf, 0x27,
};

struct okhash seg2okhash = {2,
/* Version 2.31 of the 4758 OS, "CCA 2.31 & PKCS#11 Segment-2" */
	0xee, 0xd7, 0xa0, 0x73, 0xa9, 0xd6, 0x0c, 0x04,
	0x57, 0x23, 0x82, 0x78, 0x87, 0x72, 0x27, 0x6b,
	0x99, 0xdd, 0xc8, 0xa0,
/* Version 2.41-2.42 of the 4758 OS, "2.41 CP/Q++" */
	0x4d, 0xb7, 0x7c, 0x4e, 0x47, 0x92, 0xe3, 0xd5,
	0xbc, 0x4a, 0x48, 0xed, 0x0f, 0x40, 0xde, 0x42,
	0x69, 0x8e, 0xbb, 0x30,
};

struct okhash seg3okhash = {1,
	0x52, 0xda, 0x21, 0x3a, 0x85, 0x08, 0x12, 0xd4,
	0x9f, 0x51, 0xc2, 0x74, 0x41, 0xf9, 0x03, 0x33,
	0x9e, 0x16, 0xda, 0x68,
};


static int nrecv (int fd, void *buf, unsigned count);
static void dumpbuf (FILE *f, unsigned char *buf, int len, int printoff, int breaklines);
static int doconnect (char *target, int port);


/*
 * Connect to card, reach cert chain, verify it, and if it is OK
 * we save the comm and signing keys in our files
 */
int
getkeys (char *target, int port, int firsttime)
{
	long				rc;
	unsigned long		chainbuflen;
	unsigned char		*keybuf;
	unsigned long		keybuflen;
	unsigned char		*cardid;
	unsigned long		cardidlen;
	unsigned char		md1[20], md2[20], md3[20];
	int					isepoch;
    int					s;
	unsigned char		cmd;
	unsigned short		cmdbuflen;
	unsigned char		*cmdbuf;
	RSA					*rsa;
	RSA					*commkey;
	RSA					*signkey;
	pubkey				key;
	int					i;

	printf ("Retrieving certificate chain from server...\n");
	if ((s = doconnect (target, port)) < 0)
		return s;

	/* Retrieve certificate chain */
	cmd = CMD_GETCHAIN;
	send (s, &cmd, 1, 0);
	cmdbuflen = htons(0);
	send (s, &cmdbuflen, 2, 0);

	if (nrecv (s, &cmdbuflen, 2) != 2)
	{
		perror ("read");
		exit (1);
	}
	chainbuflen = ntohs (cmdbuflen);
	if (nrecv (s, bigbuf, chainbuflen) != chainbuflen)
	{
		fprintf (stderr, "Error reading certificate chain\n");
		perror ("read");
		exit (1);
	}
	close (s);

//	printf ("Certificate chain:\n");
//	dumpbuf (stdout, bigbuf, chainbuflen, 1, 1);
//	printf ("\n");

	printf ("Validating certificate chain...\n");
	rc = certvalidate (&rsa, &isepoch, &keybuf, &keybuflen,
			md1, md2, md3, bigbuf, chainbuflen, stdout);
	if (rc < 0)
	{
		printf ("Error validating certs!\n");
		exit (1);
	} else {
		int hashok = 1, i;
		printf ("Cert chain validates OK, checking hashes...\n");
		for (i=0; i<seg1okhash.nhash; i++)
			if (memcmp (md1, seg1okhash.hash[i], 20) == 0)
				break;
		if (i == seg1okhash.nhash)
		{
			printf ("Seg 1 (miniboot, \"bios\") hash not acceptable!\n");
			hashok = 0;
		}
		for (i=0; i<seg2okhash.nhash; i++)
			if (memcmp (md2, seg2okhash.hash[i], 20) == 0)
				break;
		if (i == seg2okhash.nhash)
		{
			printf ("Seg 2 (OS) hash not acceptable!\n");
			hashok = 0;
		}
		for (i=0; i<seg3okhash.nhash; i++)
			if (memcmp (md3, seg3okhash.hash[i], 20) == 0)
				break;
		if (i == seg3okhash.nhash)
		{
			printf ("Seg 3 (application) hash not acceptable!\n");
			hashok = 0;
		}
		if (isepoch)
		{
			printf ("Epoch keys are not acceptable, they are too permanent\n");
			exit (1);
		}
		if (!hashok)
		{
//			printf ("(Not validating hash values during debugging...)\n");
			printf ("Cert chain not acceptable... exiting!\n");
			exit (1);
		} else {
			printf ("Hash is acceptable!  Proceed...\n\n");
		}
	}

	/* Now using embedded key for comm */
	RSA_free (rsa);
	commkey = rsafrombuf(keybuf, keybuflen, 0);
	signkey = rsafrombuf(keybuf, keybuflen, 1);
	if (commkey == NULL || signkey == NULL)
	{
		printf ("Bad format embedded keys in certificate chain from card\n");
		exit (1);
	}
	cardid = keyptrfrombuf (&cardidlen, keybuf, keybuflen, 2);
	if (cardidlen != CARDID_LENGTH)
	{
		printf ("Bad format embedded card ID in certificate chain from card\n");
		exit (1);
	}

	printf ("Successfully read keys for %s\n", powresource(cardid));

	gbig_init (&key.n);
	gbig_init (&key.e);
	gbig_copy (&key.n, signkey->n);
	gbig_copy (&key.e, signkey->e);
	memcpy (key.cardid, cardid, CARDID_LENGTH);
	pubkey_write (&key, signfile);

	gbig_copy (&key.n, commkey->n);
	gbig_copy (&key.e, commkey->e);
	pubkey_write (&key, commfile);

	gbig_free (&key.n);
	gbig_free (&key.e);
	RSA_free (commkey);
	RSA_free (signkey);

	/* Delete rpows.dat file if we are starting fresh */
	if (firsttime)
		unlink (rpowfile);

	return 0;
}


/*
 * Connect to card, read and print status information to fout
 */
int
getstat (char *target, int port, FILE *fout)
{
	long				rc;
	struct encstate		encdata;
	unsigned long		statbuflen;
	int					s;
	unsigned char		cmd;
	unsigned short		cmdbuflen;
	unsigned char		*encbuf1;
	unsigned long		encbuf1len;
	unsigned char		*decbuf;
	unsigned long		decbuflen;
	unsigned char		*cmdbuf;
	RSA					*rsa = RSA_new();
	pubkey				key;
	unsigned			status;
	sccAdapterInfo_t	*sccinfo;
	sccStatus_t			*oastat;
	sccClockTime_t		*scctime;
	unsigned long		*ppdspace;
	unsigned char		*pkdata;
	unsigned			pkdatalen;
	int					npkeys;
	unsigned			off;
	char				pbuf[128];
	int					i;

	printf ("Querying server card status...\n");
	if ((s = doconnect (target, port)) < 0)
		return s;

	/* Prepare encryption key */
	pubkey_read (&key, commfile);
	rsa->n = BN_new();
	rsa->e = BN_new();
	BN_copy (rsa->n, &key.n);
	BN_copy (rsa->e, &key.e);
	gbig_free (&key.n);
	gbig_free (&key.e);
	
	/* Returns a static buffer */
	if ((rc = encryptmaster (&encdata, rsa, &encbuf1, &encbuf1len)) < 0)
	{
		printf ("encryptmaster failed, code %d\n", rc);
		exit (1);
	}

	/* Retrieve status buffer */
	cmd = CMD_STAT;
	cmdbuflen = htons (encbuf1len);
	if (send (s, &cmd, 1, 0) != 1
		|| send (s, &cmdbuflen, 2, 0) != 2)
	{
		perror ("send");
		return -1;
	}

	if (send (s, encbuf1, encbuf1len, 0) != encbuf1len)
	{
		perror ("send");
		return -1;
	}

	/* Wait for response */
	if ((statbuflen = nrecv (s, bigbuf, sizeof(bigbuf))) <= 0)
	{
		fprintf (stderr, "Error, remote host closed connection\n");
		return -1;
	}
	close (s);

	status = *(unsigned *)bigbuf;
	status = htonl (status);
	if (status != 0)
	{
		fprintf (stderr, "Server reports error %d, key update may be necessary...\n",
				status);
		return status;
	}

	/* Returns a malloc buffer */
	if ((rc = decryptinput (&decbuf, &decbuflen, &encdata,
								bigbuf+sizeof(unsigned),
								statbuflen-sizeof(unsigned))) < 0)
	{
		printf ("Error, decryption of card message failed, code %d\n", rc);
		return -1;
	}


	fprintf (fout, "Status info:\n");
//dumpbuf (fout, decbuf, decbuflen, 1, 1);
//fprintf (fout, "\n");

	sccinfo = (sccAdapterInfo_t *)(decbuf + sizeof(unsigned long));
	off = UP4(ntohl (*(unsigned long *)decbuf) + sizeof(unsigned long));
	oastat = (sccStatus_t *)(decbuf+off+sizeof(unsigned long));
	off += UP4(ntohl (*(unsigned long *)(decbuf+off)) + sizeof(unsigned long));
	scctime = (sccClockTime_t *)(decbuf+off+sizeof(unsigned long));
	off += UP4(ntohl (*(unsigned long *)(decbuf+off)) + sizeof(unsigned long));
	ppdspace = (unsigned long *)(decbuf+off+sizeof(unsigned long));
	off += UP4(ntohl (*(unsigned long *)(decbuf+off)) + sizeof(unsigned long));
	ppdspace[0] = ntohl(ppdspace[0]);
	ppdspace[1] = ntohl(ppdspace[1]);
	pkdata = (unsigned char *)(decbuf+off+sizeof(unsigned long));
	off += UP4(ntohl (*(unsigned long *)(decbuf+off)) + sizeof(unsigned long));
	pkdatalen = decbuf + off - pkdata;

	strncpy (pbuf, sccinfo->VPD.pn, sizeof(sccinfo->VPD.pn));
	pbuf[sizeof(sccinfo->VPD.pn)] = 0;
	fprintf (fout, "Part number: %s\n", pbuf);

	strncpy (pbuf, sccinfo->VPD.ec, sizeof(sccinfo->VPD.ec));
	pbuf[sizeof(sccinfo->VPD.ec)] = 0;
	fprintf (fout, "Engineering change level: %s\n", pbuf);

	strncpy (pbuf, sccinfo->VPD.sn, sizeof(sccinfo->VPD.sn));
	pbuf[sizeof(sccinfo->VPD.sn)] = 0;
	fprintf (fout, "Serial number: %s\n", pbuf);

	strncpy (pbuf, sccinfo->VPD.fn, sizeof(sccinfo->VPD.fn));
	pbuf[sizeof(sccinfo->VPD.fn)] = 0;
	fprintf (fout, "FRU number: %s\n", pbuf);

	strncpy (pbuf, sccinfo->VPD.mf, sizeof(sccinfo->VPD.mf));
	pbuf[sizeof(sccinfo->VPD.mf)] = 0;
	fprintf (fout, "Manufacturing location code: %s\n", pbuf);

	strncpy (pbuf, sccinfo->VPD.ds, sizeof(sccinfo->VPD.ds));
	pbuf[sizeof(sccinfo->VPD.ds)] = 0;
	fprintf (fout, "Description: %s\n", pbuf);

	fprintf (fout, "Power On Self Test (POST) versions: %d, %d\n",
			sccinfo->POST0Version,
			sccinfo->POST1Version);

	fprintf (fout, "Miniboot versions: %d, %d\n",
			sccinfo->MiniBoot0Version,
			sccinfo->MiniBoot1Version);

	fprintf (fout, "OS version: %d\n", scctohs(sccinfo->OS_Version));
	fprintf (fout, "CPU speed (MHz): %d\n", scctohs(sccinfo->CPU_Speed));
	fprintf (fout, "DES speed (MHz): %s\n",
		(sccinfo->DES_level==0) ? "(not supported)" :
		(sccinfo->DES_level==1) ? "25" :
		(sccinfo->DES_level==2) ? "30" : "30 or more");
	fprintf (fout, "RSA max bits: %s\n",
		(sccinfo->RSA_level==0) ? "(not supported)" :
		(sccinfo->RSA_level==1) ? "1024" :
		(sccinfo->RSA_level==2) ? "2048" :
		(sccinfo->RSA_level==3) ? "2048" : "2048 or more");

	fprintf (fout, "Tamper bits: 0x%02x\n", sccinfo->HardwareStatus);

	fprintf (fout, "Adapter ID: ");
	dumpbuf (fout, sccinfo->AdapterID, sizeof(sccinfo->AdapterID), 0, 0);

	fprintf (fout, "Flash size: %d\n", sccinfo->flashSize*64*1024);
	fprintf (fout, "Flash free space: %d\n", ppdspace[0]);
	fprintf (fout, "BBRAM size: %d\n", sccinfo->bbramSize*1024);
	fprintf (fout, "BBRAM free space: %d\n", ppdspace[1]);
	fprintf (fout, "DRAM size: %d\n", sccinfo->dramSize*1024);
	fprintf (fout, "\n");

	fprintf (fout, "PIC version: %d\n",
				scctohs(oastat->rom_status.pic_version));
	fprintf (fout, "ROM version: %d\n",
				scctohs(oastat->rom_status.rom_version));
	fprintf (fout, "Page 1 certified: %d\n",
				oastat->rom_status.page1_certified);
	fprintf (fout, "Boot count left: 0x%x\n",
				scctohs(oastat->rom_status.boot_count_left));
	fprintf (fout, "Boot count right: 0x%x\n",
				scctohl(oastat->rom_status.boot_count_right));
	fprintf (fout, "Init state: %d\n",
				oastat->rom_status.init_state);
	fprintf (fout, "Segment 2 state: %d\n",
				oastat->rom_status.seg2_state);
	fprintf (fout, "Segment 3 state: %d\n",
				oastat->rom_status.seg3_state);
	fprintf (fout, "Segment 2 owner: %d\n",
				scctohs(oastat->rom_status.owner2));
	fprintf (fout, "Segment 3 owner: %d\n",
				scctohs(oastat->rom_status.owner3));
	fprintf (fout, "Active segment 1: %d\n",
				oastat->rom_status.active_seg1);

	fprintf (fout, "\n");

	fprintf (fout, "Card time: %4d/%02d/%02d %02d:%02d:%02d.%02d\n",
			scctohs(scctime->year), scctime->month,
			scctime->day, scctime->hour,
			scctime->minute, scctime->second,
			scctime->hundredths);

	if (sccinfo->HardwareStatus & 1)
		fprintf (fout, "\n***WARNING, LOW BATTERY, CARD FAILURE IS IMMINENT***\n"
				"PLEASE REPORT THIS IMMEDIATELY TO THE RPOW SERVER OPERATOR\n");

	if (sccinfo->HardwareStatus & 0x3e)
		fprintf (fout, "\n***WARNING, SERVER CARD REPORTS TAMPER ATTACK***\n"
				"PLEASE REPORT THIS IMMEDIATELY TO THE RPOW SERVER OPERATOR\n");

	fprintf (fout, "\n");

	npkeys = pkdatalen / (KEYID_LENGTH + 2*sizeof(int));
	fprintf (fout, "%d public key%s in use\n", npkeys, (npkeys==1)?"":"s");
	for (i=0; i<npkeys; i++)
	{
		int fileid = *(int *)(pkdata + i*(KEYID_LENGTH+2*sizeof(int))
					+ KEYID_LENGTH);
		int keystat = *(int *)(pkdata + i*(KEYID_LENGTH+2*sizeof(int))
					+ KEYID_LENGTH + sizeof(int));
		fileid = ntohl(fileid);
		keystat = ntohl(keystat);
		fprintf (fout, "Key %d: fileid %d, status %s, keyid:\n  ", i,
			fileid, (keystat==PUBKEY_STATE_SIGNING)?"Sign":
					(keystat==PUBKEY_STATE_ACTIVE)?"Active":
					(keystat==PUBKEY_STATE_INACTIVE)?"Disabled":"???");
		dumpbuf (fout, pkdata + i*(KEYID_LENGTH+2*sizeof(int)), KEYID_LENGTH,
					0, 0);
	}

	free (decbuf);

	return 0;
}


/*
 * Given a memory BIO, we send it to the 4758 and get a
 * response back, which we put back into the BIO for the caller
 * to read.
 */
int
comm4758 (BIO *bio, char *target, int port, pubkey *signkey)
{
	long				rc;
	struct encstate		encdata;
	unsigned char		*msgbuf;
	long				msgbuflen;
	unsigned char		*decbuf;
	unsigned long		decbuflen;
	unsigned char		*encbuf1;
	unsigned long		encbuf1len;
	unsigned char		*encbuf2;
	unsigned long		encbuf2len;
	unsigned long		replybuflen;
    int					s;
	unsigned char		cmd;
	unsigned short		cmdbuflen;
	unsigned char		*cmdbuf;
	RSA					*rsa = RSA_new();
	pubkey				key;
	unsigned			status;

	pubkey_read (&key, commfile);
	rsa->n = BN_new();
	rsa->e = BN_new();
	BN_copy (rsa->n, &key.n);
	BN_copy (rsa->e, &key.e);
	gbig_free (&key.n);
	gbig_free (&key.e);
	
	msgbuflen = BIO_get_mem_data (bio, &msgbuf);
	if (msgbuflen <= 0)
	{
		fprintf (stderr, "No data to pass to remote server\n");
		exit (1);
	}

	/* Returns a static buffer */
	if ((rc = encryptmaster (&encdata, rsa, &encbuf1, &encbuf1len)) < 0)
	{
		printf ("encryptmaster failed, code %d\n", rc);
		exit (1);
	}
	
	/* Returns a malloc buffer */
	if ((rc = encryptoutput (&encdata, msgbuf, msgbuflen,
						&encbuf2, &encbuf2len)) < 0)
	{
		printf ("encryptoutput failed, code %d\n", rc);
		exit (1);
	}

	if ((s = doconnect (target, port)) < 0)
		return s;
	cmd = CMD_SIGN;
	cmdbuflen = htons (CARDID_LENGTH + encbuf1len + encbuf2len);
	if (send (s, &cmd, 1, 0) != 1
		|| send (s, &cmdbuflen, 2, 0) != 2)
	{
		perror ("send");
		return -1;
	}

	if (send (s, signkey->cardid, CARDID_LENGTH, 0) != CARDID_LENGTH
		|| send (s, encbuf1, encbuf1len, 0) != encbuf1len
		|| send (s, encbuf2, encbuf2len, 0) != encbuf2len)
	{
		perror ("send");
		return -1;
	}
	free (encbuf2);

	if ((replybuflen = nrecv (s, bigbuf, sizeof(bigbuf))) <= 0)
	{
		fprintf (stderr, "Error, remote host closed connection\n");
		return -1;
	}
	close (s);

	status = *(unsigned *)bigbuf;
	status = htonl (status);
	if (status != 0)
	{
		fprintf (stderr, "Server reports error %d, key update may be necessary...\n",
				status);
		return status;
	}

	/* Returns a malloc buffer */
	if ((rc = decryptinput (&decbuf, &decbuflen, &encdata,
								bigbuf+sizeof(unsigned),
								replybuflen-sizeof(unsigned))) < 0)
	{
		printf ("Error, decryption of card message failed, code %d\n", rc);
		return -1;
	}

	BIO_reset (bio);
	BIO_write (bio, decbuf, decbuflen);

	free (decbuf);

	return 0;
}

static void
dumpbuf (FILE *f, unsigned char *buf, int len, int printoff, int breaklines)
{
	int i;
	int off = 0;

	for (i=0; i<len; i++)
	{
		if (printoff && (i%16 == 0)) {
			printf ("%04x  ", off);
			off += 16;
		}
		printf ("%02x%s", buf[i], (breaklines&&((i+1)%16 == 0)) ? "\n" : " ");
	}
	if (len%16 != 0)
		printf ("\n");
}

/* Support SOCKS V5 for anonymity */
static int
dosocksconnect (char *target, int port)
{
	SOCKET				s;
	struct sockaddr_in	sockaddr;
	struct hostent		*targetinfo;
	int					hostlen = strlen(target);
	unsigned char		msg[300];

	if (hostlen + 7 > sizeof(msg)) {
		fprintf (stderr, "Host name %s is too long\n", target);
		return -1;
	}

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror ("socket");
		return -1;
	}
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(socksport);
	if (!(targetinfo = gethostbyname(sockshost))) {
		fprintf (stderr, "Unknown SOCKS host machine name %s\n", sockshost);
		return -1;
	}
	if (!targetinfo->h_addr_list) {
		fprintf (stderr, "No address information available for %s\n",
			 target);
		return -1;
	}
	sockaddr.sin_addr.s_addr = **(u_long **)targetinfo->h_addr_list;

	if (connect (s, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		perror ("connect");
		return -1;
	}

	/* See RFC 1928 for SOCKS V5 */
	msg[0] = 5;	/* version */
	msg[1] = 1;	/* number of authenticator methods */
	msg[2] = 0;	/* 0 means no authentication */
	if (send (s, msg, 3, 0) != 3) {
		perror ("send");
		return -1;
	}

	/* Reply: version, selected auth */
	if (recv (s, msg, 2, 0) != 2) {
		perror ("recv");
		return -1;
	}

	if (msg[0] != 5 || msg[1] != 0) {
		fprintf (stderr, "Unable to authenticate to SOCKS server %s\n",
			sockshost);
		return -1;
	}

	msg[0] = 5;	/* version */
	msg[1] = 1;	/* command: connect(1) */
	msg[2] = 0;	/* reserved */
	msg[3] = 3; /* address type */
	msg[4] = (unsigned char)hostlen;
	strcpy (msg+5, target);
	msg[5+hostlen] = (unsigned char)(port >> 8);
	msg[6+hostlen] = (unsigned char)port;

	if (send (s, msg, hostlen+7, 0) != hostlen+7) {
		perror ("send");
		return -1;
	}

	if (recv (s, msg, sizeof(msg), 0) < 7) {
		perror ("recv");
		return -1;
	}

	if (msg[0] != 5 || msg[1] != 0) {
		fprintf (stderr, "Socks error %d\n", msg[1]);
		return -1;
	}

	/* Success! */

	return s;
}

static int
doconnect (char *target, int port)
{
	SOCKET				s;
	struct sockaddr_in	sockaddr;
	struct hostent		*targetinfo;

#if defined(_WIN32)
	WSAStartup (0x0101, &ws);
#endif

	if (usesocks)
		return dosocksconnect (target, port);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror ("socket");
		return -1;
	}
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	if (!(targetinfo = gethostbyname(target))) {
		fprintf (stderr, "Unknown target machine name\n");
		return -1;
	}
	if (!targetinfo->h_addr_list) {
		fprintf (stderr, "No address information available for %s\n",
			 target);
		return -1;
	}
	sockaddr.sin_addr.s_addr = **(u_long **)targetinfo->h_addr_list;

	if (connect (s, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		perror ("connect");
		return -1;
	}
	return s;
}

/* Read data from socket until we reach count bytes, or error */
static int
nrecv (int fd, void *buf, unsigned count)
{
	unsigned char *cbuf = buf;
	int err, nr = 0;

	while (nr < count)
	{
		err = recv (fd, cbuf+nr, count-nr, 0);
		if (err <= 0)
			return nr;
		nr += err;
	}
	return nr;
}
