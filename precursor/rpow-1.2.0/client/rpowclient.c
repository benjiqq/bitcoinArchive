/*
 * rpowclient.c
 *	External entry points into RPOW client library
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
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/buffer.h>
#include "rpowclient.h"
#include "rpowcli.h"
#include "certvalid.h"

#if defined(_WIN32)
#define ntohl(x) ((((x)>>24)&0xff)|(((x)>>8)&0xff00)| \
					(((x)&0xff00)<<8)|(((x)&0xff)<<24))
#define htonl	ntohl
#define strcasecmp	stricmp
#endif

/* Maximum number of in or out items in an exchange */
#define MAXCOUNT	10

/* Maximum size of config file line */
#define MAXLINE	128

/* File names for storing keys and data items */
char *rpowfile;
char *signfile;
char *commfile;

/* Host and port to use by default */
char targethost[256];
int targetport = DEFAULTPORT;

/* SOCKS V5 host and port, optional */
int usesocks = 0;
char sockshost[256];
int socksport;

/* Temporary, the one public signing key we know about */
pubkey signpubkey;

char *staterr[] = {
	"",
	"Already seen rpow value",
	"Invalid rpow format, software update may be necessary",
	"Insufficient hashcash bits",
	"Invalid hashcash time field",
	"New rpow values not equal to old ones",
	"Old rpow key being used, update is needed",
	"Invalid message format, update software",
	"Incompatible resource string in hashcash",
	"Unknown RPOW creation key",
	"RPEND format invalid, software update may be necessary",
	"RPOW/POW token is for a different RPOW server",
};

static void server_write (int npow, rpow **rpows, int npend, rpowpend **rpends,
	rpowio *rpio, pubkey *signkey);


/*
 * Given a set of input rpows, and the desired number and denomination
 * of output rpows, do an exchange at the server and return a status
 * code and, if OK, the output rpows.  Output array *rpout should be
 * pre-allocated as an array of pointers to rpow, nout items long.
 */
int
server_exchange (rpow **rpout, char *target, int port, int nin, rpow **rpin,
			int nout, int *outvals, pubkey *signkey)
{
	BIO *bio = BIO_new(BIO_s_mem());
	rpowio *rpio = rp_new_from_bio (bio);
	rpowpend **rpend;
	uchar stat;
	unsigned insum = 0;
	unsigned outsum = 0;
	int i;

signpubkey = *signkey;

	if (nin > MAXCOUNT || nout > MAXCOUNT)
	{
		fprintf (stderr, "Server only accepts %d input or output values in one exchange\n", MAXCOUNT);
		return -1;
	}

	for (i=0; i<nin; i++)
	{
		insum += (1 << (rpin[i]->value - RPOW_VALUE_MIN));
	}

	for (i=0; i<nout; i++)
	{
		outsum += (1 << (outvals[i] - RPOW_VALUE_MIN));
	}

	if (insum != outsum)
	{
		fprintf (stderr, "Input RPOW values 0x%x not equal to output values 0x%x\n", insum, outsum);
		return -1;
	}


	rpend = malloc (nout * sizeof (rpowpend *));
	for (i=0; i<nout; i++)
		rpend[i] = rpowpend_gen (outvals[i], 0, signkey);

	/* Output formatted request to bio buffer via rpio */
	server_write (nin, rpin, nout, rpend, rpio, signkey);

	/* Do the exchange with the IBM4758 */
	if (comm4758 (bio, target, port, signkey) != 0)
	{
		fprintf (stderr, "Unable to communicate with remote server\n");
		for (i=0; i<nout; i++)
			rpowpend_free (rpend[i]);
		free (rpend);
		rp_free (rpio);
		return -2;
	}

	/* Read results. bio buffer rpio points at holds the output from server. */
	rp_read (rpio, &stat, 1);
	if (stat != 0)
	{
		fprintf (stderr, "Exchange not accepted by server: %s\n", staterr[stat]);
		for (i=0; i<nout; i++)
			rpowpend_free (rpend[i]);
		free (rpend);
		rp_free (rpio);
		return -100-stat;
	}

	for (i=0; i<nout; i++)
	{
		rpout[i] = rpowpend_rpow (rpend[i], signkey, rpio);
		rpowpend_free (rpend[i]);
	}
	free (rpend);
	rp_free (rpio);

	for (i=0; i<nout; i++)
	{
		if (rpout[i] == NULL)
		{
			fprintf (stderr, "Bad value received from server!\n");
			return -3;
		}
	}

	return 0;
}


static void
server_write (int npow, rpow **rpows, int npend, rpowpend **rpends,
			rpowio *rpio, pubkey *signkey)
{
	int val;
	int i;

	rp_write (rpio, signkey->keyid, sizeof(signkey->keyid));
	val = htonl(npow);
	rp_write (rpio, &val, sizeof(val));
	for (i=0; i<npow; i++)
		rpow_write (rpows[i], rpio);
	val = htonl(npend);
	rp_write (rpio, &val, sizeof(val));
	for (i=0; i<npend; i++)
		rpowpend_write (rpends[i], rpio);
}

/*
 * Read a config line.  Return keyword and value.
 * On EOF return *key and *val as NULL.  Skip bad lines but
 * print a message.
 */
static void
readconfigline (FILE *f, char **key, char **val)
{
	static char linebuf[MAXLINE];
	int linebeg, lineend;
	int valbeg, keyend;
	static char *eq;

	*key = NULL;
	*val = NULL;

	for ( ; ; )
	{
		if (fgets (linebuf, sizeof(linebuf), f) == NULL)
			return;

		linebuf[MAXLINE-1] = '\0';
		lineend = strlen(linebuf);
		while (lineend > 0 && isspace (linebuf[lineend-1]))
			--lineend;
		linebuf[lineend] = '\0';
		for (linebeg = 0; linebeg<lineend; linebeg++)
			if (!isspace(linebuf[linebeg]))
				break;
		if (lineend-linebeg == 0 || linebuf[linebeg] == '#')
			continue;

		eq = strchr (linebuf+linebeg, '=');
		if (eq == NULL)
		{
			fprintf (stderr, "Bad config file line: %s\n", linebuf);
			continue;
		}
		valbeg = eq - linebuf + 1;
		while (valbeg < lineend && isspace(linebuf[valbeg]))
			++valbeg;
		if (valbeg == lineend)
		{
			fprintf (stderr, "Bad config file line: %s\n", linebuf);
			continue;
		}
		keyend = eq - linebuf - 1;
		while (keyend > linebeg && isspace(linebuf[keyend]))
			--keyend;
		if (keyend == linebeg)
		{
			fprintf (stderr, "Bad config file line: %s\n", linebuf);
			continue;
		}
		linebuf[keyend+1] = '\0';
		break;
	}
	*key = linebuf + linebeg;
	*val = linebuf + valbeg;
	return;
}

static void
readconfig (char *fname)
{
	FILE *f = fopen (fname, "r");
	char *host, *pport;
	char *key, *val;
	int gothost = 0;

	if (f == NULL)
	{
		fprintf (stderr, "Unable to open config file %s\n", fname);
		exit (1);
	}

	for ( ; ; )
	{
		readconfigline (f, &key, &val);
		if (key == NULL && val == NULL)
			break;
		if (strcasecmp (key, "host") == 0)
		{
			host = val;
			pport = strchr (host, ':');
			if (pport != NULL)
			{
				*pport++ = '\0';
				targetport = atoi(pport);
				if (targetport <= 0 || targetport >= 65536)
				{
					fprintf (stderr, "Illegal port number %d in config file %s\n",
						targetport, fname);
					exit (1);
				}
			}
			strcpy (targethost, host);
			gothost = 1;
		}
		else if (strcasecmp (key, "socks5") == 0)
		{
			host = val;
			pport = strchr (host, ':');
			if (pport == NULL)
			{
				fprintf (stderr, "Missing socks port number in config file %s\n",
						fname);
				exit (1);
			}
			*pport++ = '\0';
			socksport = atoi(pport);
			if (socksport <= 0 || socksport >= 65536)
			{
				fprintf (stderr, "Illegal socks port number %d in config file %s\n",
					socksport, fname);
				exit (1);
			}
			strcpy (sockshost, host);
			usesocks = 1;
		}
		else
		{
			fprintf (stderr, "Unrecognized keyword %s in config file %s\n",
				key, fname);
			exit (1);
		}
	}

	fclose (f);

	if (!gothost)
	{
		fprintf (stderr, "Missing host entry in config file %s\n", fname);
		exit (1);
	}
}

void
initfilenames ()
{
	char *rpowdir = getenv ("RPOW_PATH");
	char *configfile;
	struct stat rpowstat;
	int rpowmalloc = 0;

	if (rpowdir == NULL)
	{
		char *homedir = getenv ("HOME");
		if (homedir == NULL)
		{
			fprintf (stderr, "Unable to locate user's home directory\n");
			exit (1);
		}
		rpowdir = malloc (strlen(homedir) + 1 + strlen(RPOWDIR) + 1);
		strcpy (rpowdir, homedir);
		if (rpowdir[strlen(rpowdir)-1] != '/')
			strcat (rpowdir, "/");
		strcat (rpowdir, RPOWDIR);
		rpowmalloc = 1;
	}

	if (stat (rpowdir, &rpowstat) != 0 || !(rpowstat.st_mode & S_IFDIR))
	{
		fprintf (stderr, "RPOW directory %s does not exist\n", rpowdir);
		exit (1);
	}

	signfile = malloc (strlen(rpowdir) + 1 + strlen (SIGNFILE) + 1);
	strcpy (signfile, rpowdir);
	if (signfile[strlen(signfile)-1] != '/')
		strcat (signfile, "/");
	strcat (signfile, SIGNFILE);

	rpowfile = malloc (strlen(rpowdir) + 1 + strlen (RPOWFILE) + 1);
	strcpy (rpowfile, rpowdir);
	if (rpowfile[strlen(rpowfile)-1] != '/')
		strcat (rpowfile, "/");
	strcat (rpowfile, RPOWFILE);

	commfile = malloc (strlen(rpowdir) + 1 + strlen (COMMFILE) + 1);
	strcpy (commfile, rpowdir);
	if (commfile[strlen(commfile)-1] != '/')
		strcat (commfile, "/");
	strcat (commfile, COMMFILE);

	/* Now read config file */
	configfile = malloc (strlen(rpowdir) + 1 + strlen (CONFIGFILE) + 1);
	strcpy (configfile, rpowdir);
	if (configfile[strlen(configfile)-1] != '/')
		strcat (configfile, "/");
	strcat (configfile, CONFIGFILE);
	readconfig (configfile);
	free (configfile);

	if (rpowmalloc)
		free (rpowdir);
}

