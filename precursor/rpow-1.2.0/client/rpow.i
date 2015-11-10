%module rpow
%include "carrays.i"

%{
#include <fcntl.h>
#include "rpowclient.h"
%}


#define RPOW_VALUE_MIN	20
#define RPOW_VALUE_MAX	50

#  define KEYID_LENGTH	20
#  define CARDID_LENGTH	14

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

/* Define new_rpowarray(n), delete_rpowarray(arr),
 * rpowarray_getitem(arr,n), rpowarray_setitem(arr,n,val)
 */
%array_functions(rpow *, rpowarray)

int
nexchange(rpow *rpout[], rpow *rpin[], int nin, int ov1, int ov2=0, int ov3=0,
int ov4=0, int ov5=0, int ov6=0, int ov7=0, int ov8=0, int ov9=0, int ov10=0);

int
zexchange(rpow *rp1, rpow *rp2, rpow *rp3, rpow *rp4=0, rpow *rp5=0,
rpow *rp6=0, rpow *rp7=0, rpow *rp8=0, rpow *rp9=0, rpow *rp10=0, rpow *rp11=0,
rpow *rp12=0, rpow *rp13=0, rpow *rp14=0, rpow *rp15=0, rpow *rp16=0,
rpow *rp17=0, rpow *rp18=0, rpow *rp19=0, rpow *rp20=0, rpow *rp21=0);

void rpow_free(rpow *rp);

%inline
%{
#define RPOW_VALUE_MIN	20
#define RPOW_VALUE_MAX	50

pubkey signkey;

rpow *
gen(int value)
{
	if (value < RPOW_VALUE_MIN || value > RPOW_VALUE_MAX)
		return NULL;
	return rpow_gen(value, signkey.cardid);
}

rpow *
exchange(rpow *rpin)
{
	rpow *rpout = NULL;
	int outval;
	int status;

	if (rpin == NULL)
		return NULL;
	outval = rpin->value;
	status = server_exchange (&rpout, targethost, targetport, 1, &rpin, 1,
		&outval, &signkey);
	if (status != 0)
		return NULL;
	return rpout;
}

/* This lets you do nexchange(rpo, rpi, 4, 23, 23) to turn 4 22's to 2 23's */
int
nexchange(rpow *rpout[], rpow *rpin[], int nin, int ov1, int ov2, int ov3,
int ov4, int ov5, int ov6, int ov7, int ov8, int ov9, int ov10)
{
	int outvals[10];
	int nout;
	int status;

	if (nin > 10)
		return -1;
	nout = 0;
	outvals[nout++] = ov1;
	if (ov2)
		outvals[nout++] = ov2;
	if (ov3)
		outvals[nout++] = ov3;
	if (ov4)
		outvals[nout++] = ov4;
	if (ov5)
		outvals[nout++] = ov5;
	if (ov6)
		outvals[nout++] = ov6;
	if (ov7)
		outvals[nout++] = ov7;
	if (ov8)
		outvals[nout++] = ov8;
	if (ov9)
		outvals[nout++] = ov9;
	if (ov10)
		outvals[nout++] = ov10;

	status = server_exchange (rpout, targethost, targetport, nin, rpin,
		nout, outvals, &signkey);
	return status;
}

int
zexchange(rpow *rp1, rpow *rp2, rpow *rp3, rpow *rp4, rpow *rp5,
rpow *rp6, rpow *rp7, rpow *rp8, rpow *rp9, rpow *rp10, rpow *rp11,
rpow *rp12, rpow *rp13, rpow *rp14, rpow *rp15, rpow *rp16,
rpow *rp17, rpow *rp18, rpow *rp19, rpow *rp20, rpow *rp21)
{
	rpow *rpi[10];
	rpow *rpo[10];
	rpow *rpout[10];
	int outvals[10];
	int nin = 0;
	int nout = 0;
	int status;
	int i;

	do {
		if (rp1) rpi[nin++] = rp1; else break;
		if (rp2) rpi[nin++] = rp2; else break;
		if (rp3) rpi[nin++] = rp3; else break;
		if (rp4) rpi[nin++] = rp4; else break;
		if (rp5) rpi[nin++] = rp5; else break;
		if (rp6) rpi[nin++] = rp6; else break;
		if (rp7) rpi[nin++] = rp7; else break;
		if (rp8) rpi[nin++] = rp8; else break;
		if (rp9) rpi[nin++] = rp9; else break;
		if (rp10) rpi[nin++] = rp10; else break;
		if (rp11) rpi[nin++] = rp11; else break;
		if (rp12) rpi[nin++] = rp12; else break;
		if (rp13) rpi[nin++] = rp13; else break;
		if (rp14) rpi[nin++] = rp14; else break;
		if (rp15) rpi[nin++] = rp15; else break;
		if (rp16) rpi[nin++] = rp16; else break;
		if (rp17) rpi[nin++] = rp17; else break;
		if (rp18) rpi[nin++] = rp18; else break;
		if (rp19) rpi[nin++] = rp19; else break;
		if (rp20) rpi[nin++] = rp20; else break;
		if (rp21) rpi[nin++] = rp21; else break;
	} while (0);

	nout = -nin - 2;

	do {
		if (++nout >= 0) if (rp1) rpo[nout] = rp1; else break;
		if (++nout >= 0) if (rp2) rpo[nout] = rp2; else break;
		if (++nout >= 0) if (rp3) rpo[nout] = rp3; else break;
		if (++nout >= 0) if (rp4) rpo[nout] = rp4; else break;
		if (++nout >= 0) if (rp5) rpo[nout] = rp5; else break;
		if (++nout >= 0) if (rp6) rpo[nout] = rp6; else break;
		if (++nout >= 0) if (rp7) rpo[nout] = rp7; else break;
		if (++nout >= 0) if (rp8) rpo[nout] = rp8; else break;
		if (++nout >= 0) if (rp9) rpo[nout] = rp9; else break;
		if (++nout >= 0) if (rp10) rpo[nout] = rp10; else break;
		if (++nout >= 0) if (rp11) rpo[nout] = rp11; else break;
		if (++nout >= 0) if (rp12) rpo[nout] = rp12; else break;
		if (++nout >= 0) if (rp13) rpo[nout] = rp13; else break;
		if (++nout >= 0) if (rp14) rpo[nout] = rp14; else break;
		if (++nout >= 0) if (rp15) rpo[nout] = rp15; else break;
		if (++nout >= 0) if (rp16) rpo[nout] = rp16; else break;
		if (++nout >= 0) if (rp17) rpo[nout] = rp17; else break;
		if (++nout >= 0) if (rp18) rpo[nout] = rp18; else break;
		if (++nout >= 0) if (rp19) rpo[nout] = rp19; else break;
		if (++nout >= 0) if (rp20) rpo[nout] = rp20; else break;
		if (++nout >= 0) if (rp21) rpo[nout] = rp21; else break;
	} while (0);

	if (nin < 1 || nin > 10 || nout < 1 || nout > 10)
		return -1;

	for (i=0; i<nout; i++)
		outvals[i] = rpo[i]->value;
	for (i=0; i<nin; i++)
		printf ("%d ", rpi[i]->value);
	printf ("0 ");
	for (i=0; i<nout; i++)
		printf ("%d ", rpo[i]->value);
	printf ("\n");

	status = server_exchange (rpout, targethost, targetport, nin, rpi,
		nout, outvals, &signkey);

	if (status != 0)
		return status;

	nout = -nin - 2;

	do {
		if (++nout >= 0) if (rp1) *rp1 = *rpout[nout];
		if (++nout >= 0) if (rp2) *rp2 = *rpout[nout];
		if (++nout >= 0) if (rp3) *rp3 = *rpout[nout];
		if (++nout >= 0) if (rp4) *rp4 = *rpout[nout];
		if (++nout >= 0) if (rp5) *rp5 = *rpout[nout];
		if (++nout >= 0) if (rp6) *rp6 = *rpout[nout];
		if (++nout >= 0) if (rp7) *rp7 = *rpout[nout];
		if (++nout >= 0) if (rp8) *rp8 = *rpout[nout];
		if (++nout >= 0) if (rp9) *rp9 = *rpout[nout];
		if (++nout >= 0) if (rp10) *rp10 = *rpout[nout];
		if (++nout >= 0) if (rp11) *rp11 = *rpout[nout];
		if (++nout >= 0) if (rp12) *rp12 = *rpout[nout];
		if (++nout >= 0) if (rp13) *rp13 = *rpout[nout];
		if (++nout >= 0) if (rp14) *rp14 = *rpout[nout];
		if (++nout >= 0) if (rp15) *rp15 = *rpout[nout];
		if (++nout >= 0) if (rp16) *rp16 = *rpout[nout];
		if (++nout >= 0) if (rp17) *rp17 = *rpout[nout];
		if (++nout >= 0) if (rp18) *rp18 = *rpout[nout];
		if (++nout >= 0) if (rp19) *rp19 = *rpout[nout];
		if (++nout >= 0) if (rp20) *rp20 = *rpout[nout];
		if (++nout >= 0) if (rp21) *rp21 = *rpout[nout];
	} while (0);

	return 0;
}


/* Store the rpow in the rpows file, return 0 on success */
int
store (rpow *rp)
{
	return rpow_to_store(rp);
}



/* Helper for load - break num outval items to create numo of size outval */
static int dobreakval (int num, int val, int numo, int outval)
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
				store (rp[i]);
			return -1;
		}
	}

	for (i=0; i<numo; i++)
		outvals[i] = outval;

	err = server_exchange (rpnew, targethost, targetport, num, rp,
		numo, outvals, &signkey);
	if (err != 0)
	{
		for (i=0; i<num; i++)
			store (rp[i]);
		return err;
	}

	for (i=0; i<numo; i++)
		store (rpnew[i]);
	return 0;
}

/* Helper for load - break items to create some of size val */
static int dobreak (int val)
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
		if ((err = dobreakval (1, tval, 8, tval-3)) < 0)
			return err;
		tval -= 3;
		count = 8;
	}

	maxcount = 1 << (3 - (tval - val));
	if (count > maxcount)
		count = maxcount;

	err = dobreakval (count, tval, count << (tval-val), val);
	return err;
}

rpow *
load (int value)
{
	rpow *rp;

	if ((rp = rpow_from_store(value)) == NULL)
	{
		if (dobreak (value) == 0)
			rp = rpow_from_store(value);
	}
	return rp;
}

/* Count the rpows in the data file */
int
countvals (int val)
{
	int counts[RPOW_VALUE_MAX - RPOW_VALUE_MIN + 1];

	if (val < RPOW_VALUE_MIN || val > RPOW_VALUE_MAX)
		return 0;

	if (rpow_count(counts) < 0)
	{
		fprintf (stderr, "Unable to open rpow data storen");
		return 0;
	}

	return counts[val-RPOW_VALUE_MIN];
}

char *
to_string (rpow *rpin)
{
	if (rpin == NULL)
		return "";
	return rpow_to_string(rpin);
}

rpow *
from_string (char *str)
{
	return rpow_from_string(str);
}



%}

%init
%{
	gbig_initialize();
	initfilenames();
	pubkey_read (&signkey, signfile);
%}



/* connio.c */

/* Getkeys deletes all of the rpows if firsttime is set! */
extern int getkeys (char *target, int port, int firsttime);
extern int getstat (char *target, int port, FILE *fout);


