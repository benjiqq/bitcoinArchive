/*
 * rpowcli.c
 *	Reusable proof of work client
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "rpowcli.h"

#define RPOW_VERSION	"RPOW client version 1.1.0"

static pubkey signkey;


static int
dogen (char *target, int port, int value)
{
	rpow *rp;
	rpow *rpnew;
	int err;

	rp = rpow_gen (value, signkey.cardid);
	if (rp == NULL)
	{
		fprintf (stderr, "Unable to generate an rpow of value %d\n", value);
		exit (-1);
	}

	err = server_exchange (&rpnew, target, port, 1, &rp, 1, &value, &signkey);
	if (err != 0)
		exit (err);

	rpow_free (rp);
	if (rpow_to_store (rpnew) < 0)
		fprintf (stderr, "Error, unable to store rpow\n");

	return 0;
}


/* Continue to generate rpows until interrupted; consolidate them too */
static int
dogencontin (char *target, int port)
{
	rpow *rp[8];
	rpow *rpnew;
	int numgen;
	int genval = 29;
	int outval;
	time_t starttime, endtime;
	int err;

#ifdef __APPLE__
if (!hashcash_use_core(7))	// Only appropriate for Mac PPC
{printf ("Failed to set hashcash minting engine\n"); exit (1);}
printf ("Using hashcash core %s\n", hashcash_core_name(hashcash_core()));
#endif

	starttime = time(0);
	numgen = 0;
	for ( ; ; )
	{
		rp[numgen++] = rpow_gen (genval, signkey.cardid);
		if (rp == NULL)
		{
			fprintf (stderr, "Unable to generate an rpow of value %d\n", genval);
			exit (2);
		}
printf ("Generated an rpow of value %d\n", genval);

		if (numgen == 8)
		{
			int i;
			outval = genval + 3;
printf ("Exchanging %d rpows of value %d for one of value %d\n", numgen, genval, outval);
			err = server_exchange (&rpnew, target, port, numgen, rp,
				1, &outval, &signkey);
			if (err != 0)
{
for (i=0; i<numgen; i++)
{int j; for (j=0; j<rp[i]->idlen; j++) putchar(rp[i]->id[j]);
putchar ('\n');}
				exit (err);
}
			for (i=0; i<numgen; i++)
				rpow_free (rp[i]);
			if (rpow_to_store (rpnew) < 0)
				fprintf (stderr, "Error, unable to store rpow\n");
			rpow_free (rpnew);

			/* Adjust size so it takes 10 to 60 minutes to do 8 rpows */
			endtime = time(0);
printf ("Took %02d mins %02d secs\n", (endtime-starttime)/60, (endtime-starttime)%60);
			if (endtime - starttime < 600 && genval < RPOW_VALUE_MAX)
				++genval;
			if (endtime - starttime > 3600 && genval > RPOW_VALUE_MIN)
				--genval;
			starttime = endtime;
			numgen = 0;
		}
	}
}

/* Helper for doconsol - consolidate num items of size val */
static int doconsolval (char *target, int port, int num, int val, int outval)
{
	rpow *rp[8];
	rpow *rpnew;
	int vals[8];
	int i;
	int err;

	for (i=0; i<num; i++)
	{
		vals[i] = val;
		rp[i] = rpow_from_store (val);
		if (rp[i] == NULL)
		{
			/* Error, try to fix it as much as we can */
			while (--i >= 0)
			{
				if (rpow_to_store (rp[i]) < 0)
					fprintf (stderr, "Error, unable to store rpow\n");
			}
			return -1;
		}
	}

	err = server_exchange (&rpnew, target, port, num, rp, 1, &outval, &signkey);
	if (err != 0)
	{
		for (i=0; i<num; i++)
		{
			if (rpow_to_store (rp[i]) < 0)
				fprintf (stderr, "Error, unable to store rpow\n");
		}
		return err;
	}

	if (rpow_to_store (rpnew) < 0)
		fprintf (stderr, "Error, unable to store rpow\n");
	return 0;
}

/* Consolidate rpows into as few as possible */
static int doconsol (char *target, int port)
{
	int val;
	int count;
	int counts[RPOW_VALUE_MAX - RPOW_VALUE_MIN + 1];
	int err;

	for (val = RPOW_VALUE_MIN; val <= RPOW_VALUE_MAX; val++)
	{
		/* Count rpows of value */
		if (rpow_count (counts) < 0)
		{
			fprintf (stderr, "Unable to open rpow data store\n");
			exit (1);
		}
		count = counts[val - RPOW_VALUE_MIN];

		while (count >= 8 && val+3 <= RPOW_VALUE_MAX)
		{
			err = doconsolval (target, port, 8, val, val+3);
			if (err != 0)
				return err;
			count -= 8;
		}

		if (count >= 4 && val+2 <= RPOW_VALUE_MAX)
		{
			err = doconsolval (target, port, 4, val, val+2);
			if (err != 0)
				return err;
			count -= 4;
		}

		if (count >= 2 && val+1 <= RPOW_VALUE_MAX)
		{
			err = doconsolval (target, port, 2, val, val+1);
			if (err != 0)
				return err;
			count -= 2;
		}
	}
	return 0;
}

static int doin (char *target, int port)
{
	int bufsize, buflen;
	char *buf, *buf64;
	int nr;
	BIO *bioin;
	rpowio *rpioin;
	rpow *rp;
	rpow *rpnew;
	int err;

	/* Read from stdin */
	bufsize = 1000;
	buflen = 0;
	buf = malloc (bufsize);
	while ((nr = fread (buf, 1, bufsize-buflen, stdin)) > 0)
	{
		buflen += nr;
		if (buflen == bufsize)
		{
			bufsize *= 2;
			buf = realloc (buf, bufsize);
		}
	}
	if (strncmp (buf, "1:", 2) == 0)
	{
		buf64 = hc_to_buffer (buf, &buflen);
	} else {
		/* De-base64 */
		buf64 = malloc (buflen);
		buflen = dec64 (buf64, buf, buflen);
	}

	/* Parse as a rpow */
	bioin = BIO_new(BIO_s_mem());
	rpioin = rp_new_from_bio (bioin);
	BIO_write (bioin, buf64, buflen);
	rp = rpow_read (rpioin);
	rp_free (rpioin);

	if (rp == NULL)
	{
		fprintf (stderr, "Invalid incoming rpow format\n");
		exit (2);
	}

	err = server_exchange (&rpnew, target, port, 1, &rp,
				1, &rp->value, &signkey);
	if (err != 0)
		exit (err);

	rpow_free (rp);
	if (rpow_to_store (rpnew) < 0)
		fprintf (stderr, "Error, unable to store rpow\n");

	printf ("Received rpow item of value %d\n", rpnew->value);
	return rpnew->value;
}


/* Helper for doout - break num outval items to create numo of size outval */
static int dobreakval (char *target, int port, int num, int val,
	int numo, int outval)
{
	rpow *rp[8];
	rpow *rpnew[8];
	int vals[8];
	int outvals[8];
	int i;
	int err;

	for (i=0; i<num; i++)
	{
		vals[i] = val;
		rp[i] = rpow_from_store (val);
		if (rp[i] == NULL)
		{
			/* Error, try to fix it as much as we can */
			while (--i >= 0)
			{
				if (rpow_to_store (rp[i]) < 0)
					fprintf (stderr, "Error, unable to store rpow\n");
			}
			return -1;
		}
	}

	for (i=0; i<numo; i++)
		outvals[i] = outval;

	err = server_exchange (rpnew, target, port, num, rp, numo, outvals, &signkey);
	if (err != 0)
	{
		for (i=0; i<num; i++)
		{
			if (rpow_to_store (rp[i]) < 0)
				fprintf (stderr, "Error, unable to store rpow\n");
		}
		return err;
	}

	for (i=0; i<numo; i++)
	{
		if (rpow_to_store (rpnew[i]) < 0)
			fprintf (stderr, "Error, unable to store rpow\n");
	}
	return 0;
}

/* Helper for doout - break items to create some of size val */
static int dobreak (char *target, int port, int val)
{
	int tval;
	int counts[RPOW_VALUE_MAX-RPOW_VALUE_MIN+1];
	int count;
	int maxcount;
	int err;

	for (tval = val+1; tval <= RPOW_VALUE_MAX; tval++)
	{
		if (rpow_count(counts) < 0)
		{
			fprintf (stderr, "Unable to open rpow data store\n");
			exit (1);
		}

		count = counts[tval - RPOW_VALUE_MIN];

		if (count != 0)
			break;
	}

	if (count == 0)
		return -1;		/* Insufficient rpows */

	while (tval > val + 3)
	{
		if ((err = dobreakval (target, port, 1, tval, 8, tval-3)) < 0)
			return err;
		tval -= 3;
		count = 8;
	}

	maxcount = 1 << (3 - (tval - val));
	if (count > maxcount)
		count = maxcount;

	err = dobreakval (target, port, count, tval, count << (tval-val), val);
	return err;
}

static int doout (char *target, int port, int value)
{
	rpow *rp;
	char *ptr, *outbuf;
	BIO *bio;
	rpowio *rpio;
	int ptrlen;
	int outlen;

	rp = rpow_from_store (value);
	if (rp == NULL)
	{
		if (dobreak (target, port, value) < 0 ||
			(rp = rpow_from_store (value)) == NULL )
		{
			fprintf (stderr, "Unable to find RPOW of value %d\n", value);
			exit (2);
		}
	}

	/* Convert to base64 and output to stdout */
	bio = BIO_new(BIO_s_mem());
	rpio = rp_new_from_bio (bio);
	rpow_write (rp, rpio);
	ptrlen = BIO_get_mem_data (bio, &ptr);
	outbuf = malloc (2*ptrlen);
	outlen = enc64 (outbuf, ptr, ptrlen);
	outbuf[outlen] = '\0';
	puts (outbuf);
	free (outbuf);
	rp_free (rpio);
	return 0;
}


static int doexch (char *target, int port, int nin, int *invals,
			int nout, int *outvals)
{
	rpow **rp;
	rpow **rpnew;
	int err;
	int i;

	rp = malloc (nin * sizeof (rpow *));
	rpnew = malloc (nout * sizeof(rpow *));

	for (i=0; i<nin; i++)
	{
		rp[i] = rpow_from_store (invals[i]);
		if (rp[i] == NULL)
		{
			fprintf (stderr, "Unable to find RPOW with value %d\n", invals[i]);
			while (i-- > 0)
			{
				if (rpow_to_store (rp[i]) < 0)
					fprintf (stderr, "Error, unable to store rpow\n");
			}
			exit (2);
		}
	}

	err = server_exchange (rpnew, target, port, nin, rp,
					nout, outvals, &signkey);
	if (err != 0)
	{
		/* Try putting the ones back we puled out */
		for (i=0; i<nin; i++)
		{
			if (rpow_to_store (rp[i]) < 0)
				fprintf (stderr, "Error, unable to store rpow\n");
		}
		exit (err);
	}

	for (i=0; i<nout; i++)
	{
		if (rpow_to_store (rpnew[i]) < 0)
			fprintf (stderr, "Error, unable to store rpow\n");
		rpow_free (rpnew[i]);
	}
	for (i=0; i<nin; i++)
		rpow_free (rp[i]);
	free (rp);
	free (rpnew);

	return 0;
}


static int docount ()
{
	int expcounts[RPOW_VALUE_MAX - RPOW_VALUE_MIN + 1];
	int count;
	int exp;

	count = rpow_count (expcounts);

	if (count < 0)
	{
		fprintf (stderr, "Unable to open rpow data store\n");
		exit (1);
	}

	printf ("%d rpows in rpow data store:\n", count);

	for (exp=RPOW_VALUE_MIN; exp<=RPOW_VALUE_MAX; ++exp)
	{
		if (expcounts[exp-RPOW_VALUE_MIN] > 0)
			printf ("  value %2d: %d\n", exp, expcounts[exp-RPOW_VALUE_MIN]);
	}
	return 0;
}


static void
userr (char *pname)
{
	fprintf (stderr, "%s\n", RPOW_VERSION);
	fprintf (stderr, "Usage: %s"
		" getkeys <<<<==== (must be done first, deletes existing rpows)\n"
		"\trekey\n"
		"\tstatus\n"
		"\tgen value\n"
		"\tgencontin\n"
		"\texchange cur_val ... 0 new_val ...\n"
		"\tconsolidate\n"
		"\tin < rpowdata\n"
		"\tout value > rpowdata\n"
		"\tcount\n",
		pname);
	exit (1);
}

int
main (int ac, char **av)
{
	char *cmd;
	int nsides;
	int cmdgen, cmdout, cmdin, cmdcount, cmdexch, cmdkeys, cmdstat,
		cmdgencontin, cmdconsol;
	int cmdrekey;
	int value;

	if (ac < 2)
		userr (av[0]);

	cmd = av[1];
	cmdkeys = (strcmp (cmd, "getkeys") == 0);
	cmdgen = (strcmp (cmd, "gen") == 0);
	cmdgencontin = (strcmp (cmd, "gencontin") == 0);
	cmdout = (strcmp (cmd, "out") == 0);
	cmdin = (strcmp (cmd, "in") == 0);
	cmdcount = (strcmp (cmd, "count") == 0);
	cmdexch = (strcmp (cmd, "exchange") == 0);
	cmdconsol = (strcmp (cmd, "consolidate") == 0);
	cmdrekey = (strcmp (cmd, "rekey") == 0);
	cmdstat = (strcmp (cmd, "status") == 0);
	if (cmdkeys+cmdgen+cmdout+cmdin+cmdcount+cmdexch+cmdrekey
			+cmdstat+cmdgencontin+cmdconsol != 1)
		userr(av[0]);

	initfilenames ();

	if ((cmdout || cmdgen) && ac != 3)
		userr (av[0]);
	if ((cmdin || cmdcount || cmdkeys || cmdrekey || cmdstat || cmdgencontin
				|| cmdconsol)
			&& ac != 2)
		userr (av[0]);

	gbig_initialize();

	if (cmdcount)
		return docount();

	if (cmdstat)
		return getstat (targethost, targetport, stdout);

	if (cmdkeys || cmdrekey)
	{
		if (getkeys (targethost, targetport, cmdkeys) != 0)
		{
			fprintf (stderr, "Error retrieving and validating keys\n");
			exit (1);
		}
		exit (0);
	}

	pubkey_read (&signkey, signfile);

	if (cmdout)
	{
		value = atoi(av[2]);
		return doout(targethost, targetport, value);
	}

	if (cmdexch)
	{
		int *invals, *outvals;
		int nin, nout;
		int i;

		if (ac < 5)
			userr(av[0]);
		for (i=3; i<ac-1; i++)
		{
			if (strcmp (av[i], "0") == 0)
				break;
		}
		if (i == ac)
			userr(av[0]);
		nin = i - 2;
		nout = ac - i - 1;
		invals = malloc (nin * sizeof(int));
		outvals = malloc (nout * sizeof(int));
		for (i=0; i<nin; i++)
		{
			invals[i] = atoi(av[i+2]);
			if (invals[i] < RPOW_VALUE_MIN || invals[i] > RPOW_VALUE_MAX)
				userr(av[0]);
		}
		for (i=0; i<nout; i++)
		{
			outvals[i] = atoi(av[ac-nout+i]);
			if (outvals[i] < RPOW_VALUE_MIN || outvals[i] > RPOW_VALUE_MAX)
				userr(av[0]);
		}
		return doexch (targethost, targetport, nin, invals, nout, outvals);
	}

	if (cmdgen)
	{
		value = atoi(av[2]);
		if (value < RPOW_VALUE_MIN || value > RPOW_VALUE_MAX)
		{
			fprintf (stderr, "Illegal work value %d\n", value);
			exit (1);
		}
		return dogen (targethost, targetport, value);
	}

	if (cmdgencontin)
		return dogencontin (targethost, targetport);

	if (cmdconsol)
		return doconsol (targethost, targetport);

	if (cmdin)
		return doin (targethost, targetport);
}
