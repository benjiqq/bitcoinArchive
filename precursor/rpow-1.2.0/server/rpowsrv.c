/*
 * rpowsrv.c
 *	Host server for RPOW package
 *
 *	This runs on the host, listens for network connections,
 *	and communicates with the RPOW server running on an IBM 4758
 *	Secure Cryptographic Coprocessor card.
 */

#if defined(_WIN32)
#include <windows.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <scctypes.h>
#include <scc_host.h>
#include <scc_oa.h>
#include <scc_err.h>
#include "rpow.h"
#include "dbproof.h"

#if defined(_WIN32)
WSADATA ws;
#define sleep(n) Sleep((n)*1000);
#define ntohl(x) ((((x)>>24)&0xff)|(((x)>>8)&0xff00)| \
					(((x)&0xff00)<<8)|(((x)&0xff)<<24))
#define htonl	ntohl
#define close	closesocket
#define alarm(n)
#else
typedef int SOCKET;
#endif

#define NPOWDBS			3
#define RPOWDBNAME		"rpow%03d.db"
#define CHAINFILENAME	"certchain.dat"

#define CHAINSIZE	20000
#define SECRETSIZE	128


#define PUBKEY_STATE_SIGNING	1
#define PUBKEY_STATE_ACTIVE		2
#define PUBKEY_STATE_INACTIVE	3


DEFAGENT;


/* Bit size of RSA key used to secure communication */
#define KEYSIZE		1024

/* For blocksigs() */
#define BLOCK		1
#define UNBLOCK		0

/* How long to wait on incoming connections */
#define TIMEOUTSECS	3

unsigned char bigbuf[CHAINSIZE];
unsigned char chainbuf[CHAINSIZE];
unsigned chainlen;

int interruptflag;
int alarmflag;

sccAdapterHandle_t handle;
sccRB_t            rb;

void dumpbuf (unsigned char *buf, int len);
static int nread (int fd, void *buf, unsigned count);
long SCC_CALL _sccRequest(sccAdapterHandle_t adapter_handle, sccRB_t *request_block);
static int dokeygen (int numdbs);
static int dolisten (int port, int numdbs);
static int dorollover (int rollfileid);
static int doaddpub (char *chainfile, int dbnum);
static int dochangestate (int keynum, int enable);
static int dolowbatt (void);
static void blocksigs(int block);
static void alarmhandler (int signum);

static void
userr (char *pname)
{
	fprintf (stderr, "Usage: %s [-d workingdirectory] command args\n"
				"  Commands are:\n"
				"    initialize [cnum]\n"
				"    listen port [cnum]\n"
				"    rollover [cnum]\n"
				"    addpub chainfile [cnum]\n"
				"    disable keynum [cnum]\n"
				"    enable keynum [cnum]\n"
				"    clearlowbatt [cnum]\n"
				"    (cnum is card number, defaults to 0)\n"
				, pname);
	exit (1);
}

static char *
dbname (int n)
{
	static char buf[128];

	sprintf (buf, RPOWDBNAME, n);
	return buf;
}

/* Return how many DB files (consecutively numbered from 0) are in the CWD */
static int
dbcount ()
{
	struct stat s;
	int n = 0;

	while (stat (dbname(n), &s) == 0)
		n++;
	return n;
}

int
main(int ac, char **av)
{
	long				rc;
	sccAdapterNumber_t	adapterCount;
	int					adapterNumber = 0;
	int					port;
	int					numdbs;
	int					rolldbnum;
	FILE				*fchain;
	int					keynum;
	char				*chainfile;
	int					cmdkeygen, cmdlisten;
	int					cmdrollover, cmdlowbatt;
	int					cmdadd, cmdenable, cmddisable;

#if defined(_WIN32)
	WSAStartup (0x0101, &ws);
#endif

	if (ac < 2)
		userr (av[0]);

	if (strcmp (av[1], "-d") == 0)
	{
		if (ac < 4)
			userr (av[0]);
		if (chdir (av[2]) != 0)
		{
			fprintf (stderr, "Unable to change directory to %s\n", av[2]);
			exit (1);
		}
		/* Discard first two arguments */
		av[2] = av[0];
		av += 2;
		ac -= 2;
	}
	cmdkeygen = strcmp (av[1], "initialize") == 0;
	cmdlisten = strcmp (av[1], "listen") == 0;
	cmdrollover = strcmp (av[1], "rollover") == 0;
	cmdadd = strcmp (av[1], "addpub") == 0;
	cmdenable = strcmp (av[1], "enable") == 0;
	cmddisable = strcmp (av[1], "disable") == 0;
	cmdlowbatt = strcmp (av[1], "clearlowbatt") == 0;

	if (cmdkeygen+cmdlisten+cmdrollover+cmdadd
			+cmdenable+cmddisable+cmdlowbatt != 1)
		userr (av[0]);

	if (cmdkeygen || cmdrollover || cmdlowbatt)
	{
		if (ac > 3)
			userr (av[0]);
		if (ac == 3)
			adapterNumber = atoi(av[2]);
	}

	if (cmdlisten)
	{
		if (ac < 3 || ac > 4)
			userr (av[0]);
		port = atoi (av[2]);
		if (port < 0 || port > 65535)
		{
			fprintf (stderr, "Illegal port number %d\n", port);
			exit (1);
		}
		if (ac == 4)
			adapterNumber = atoi(av[3]);
	}

	if (cmdadd)
	{
		if (ac < 3 || ac > 4)
			userr (av[0]);
		chainfile = av[2];
		if (ac == 4)
			adapterNumber = atoi(av[3]);
	}

	if (cmdenable ||  cmddisable)
	{
		if (ac < 3 || ac > 4)
			userr (av[0]);
		keynum = atoi(av[2]);
		if (keynum < 0)
		{
			fprintf (stderr, "Illegal key number %d\n", keynum);
			exit (1);
		}
		if (ac == 4)
			adapterNumber = atoi(av[3]);
	}

	if ((rc = sccAdapterCount(&adapterCount)) != 0)
	{
		printf("sccAdapterCount failed rc = 0x%x\n",rc);
		exit(1);
	}

	if (adapterCount < adapterNumber + 1)
	{
		printf("Found %d adapters in the system; "
		   "command targeted to adapter index %d\n",
		   adapterCount,adapterNumber);
		exit(1);
	}

	if ((rc = sccOpenAdapter(adapterNumber,&handle)) != 0)
	{
		if (rc != HDDDeviceBusy)
		{
			printf("sccOpenAdapter(%d) failed rc = 0x%x\n",adapterNumber,rc);
			exit(1);
		}
		printf ("Adapter %d busy, waiting for it...\n", adapterNumber);
		while (rc == HDDDeviceBusy)
		{
			sleep (3);
			rc = sccOpenAdapter(adapterNumber, &handle);
		};
		if (rc != 0)
		{
			printf("sccOpenAdapter(%d) failed rc = 0x%x\n",adapterNumber,rc);
			exit(1);
		}
		sleep (1);
	}

	printf ("Adapter ready!\n");

	numdbs = dbcount ();

	if (cmdkeygen)
		return dokeygen (numdbs);

	if (cmdlisten)
		return dolisten (port, numdbs);

	if (cmdrollover)
		return dorollover (numdbs);

	if (cmdenable || cmddisable)
		return dochangestate (keynum, cmdenable);

	if (cmdadd)
		return doaddpub (chainfile, numdbs);

	if (cmdlowbatt)
		return dolowbatt ();

	if ((rc = sccCloseAdapter(handle)) != 0)
	{
		printf("sccCloseAdapter failed rc = 0x%x\n",rc);
		exit(1);
	}

	return 0;
}

static int
doaddpub (char *chainfile, int dbnum)
{
	long rc;
	FILE *fchain = fopen (chainfile, "rb");
	dbproof *db;
	int buflen;
	int dbcreated;

	if (fchain == NULL)
	{
		fprintf (stderr, "Unable to open file %s\n", chainfile);
		exit (1);
	}
	buflen = fread (bigbuf, 1, sizeof(bigbuf), fchain);
	fclose (fchain);

	db = opendb (dbname (dbnum), &dbcreated);
	if (!dbcreated)
	{
		fprintf (stderr, "Addpub error, old database file %s found.\n",
					dbname(dbnum));
		exit (1);
	}

	memset(&rb,0,sizeof(rb));
	rb.AgentID				= agentID;
	rb.OutBufferLength[0]	= sizeof(dbnum);
	rb.pOutBuffer[0]		= (void *)&dbnum;
	rb.OutBufferLength[1]	= buflen;
	rb.pOutBuffer[1]		= (void *)bigbuf;
	rb.UserDefined			= CMD_ADDKEY;
	if ((rc = _sccRequest(handle,&rb)) != 0)
	{
		printf("sccRequest failed rc = 0x%x\n",rc);
		sccCloseAdapter(handle);
		exit(1);
	}
	if (rb.Status != 0)
	{
		printf ("Error, status returned is %d\n", rb.Status);
		exit (2);
	}

	printf ("Successfully added key number %d from %s\n", dbnum,
				chainfile);

	return 0;
}

static int
dochangestate (int keynum, int enable)
{
	long			rc;
	int				newstate;

	newstate = enable ? PUBKEY_STATE_ACTIVE : PUBKEY_STATE_INACTIVE;

	memset(&rb,0,sizeof(rb));
	rb.AgentID				= agentID;
	rb.OutBufferLength[0]	= sizeof(keynum);
	rb.pOutBuffer[0]		= (void *)&keynum;
	rb.OutBufferLength[1]	= sizeof(newstate);
	rb.pOutBuffer[1]		= (void *)&newstate;
	rb.UserDefined			= CMD_CHANGEKEYSTATE;
	if ((rc = _sccRequest(handle,&rb)) != 0)
	{
		printf("sccRequest failed rc = 0x%x\n",rc);
		sccCloseAdapter(handle);
		exit(1);
	}
	if (rb.Status != 0)
	{
		printf ("Error, status returned is %d\n", rb.Status);
		exit (2);
	}

	printf ("Successfully %s key %d\n", enable?"enabled":"disabled",
			keynum);

	return 0;
}

static int
dolowbatt ()
{
	long			rc;

	memset(&rb,0,sizeof(rb));
	rb.AgentID				= agentID;
	rb.UserDefined			= CMD_CLEARLOWBATT;
	if ((rc = _sccRequest(handle,&rb)) != 0)
	{
		printf("sccRequest failed rc = 0x%x\n",rc);
		sccCloseAdapter(handle);
		exit(1);
	}
	if (rb.Status != 0)
	{
		printf ("Error, status returned is %d\n", rb.Status);
		exit (2);
	}

	printf ("Successfully reset low battery latch\n");

	return 0;
}

static int
dokeygen (int numdbs)
{
	long				rc;
	FILE				*fchain;
	dbproof				*db;
	int					dbcreated;
	int					i;

	if (numdbs != 0)
	{
		fprintf (stderr, "%d old database files found.  "
						"Delete before keygen\n", numdbs);
		exit (1);
	}

	for (i=0; i<=NPOWDBS; i++)
	{
		db = opendb (dbname(i), &dbcreated);
		if (!dbcreated)
		{
			fprintf (stderr, "Old database file %s found.  Delete it before keygen\n",
				dbname (i));
			exit (1);
		}
		freedb (db);
	}

	if ((fchain = fopen (CHAINFILENAME, "wb")) == NULL)
	{
		fprintf (stderr, "Unable to open chain file %s for output\n", CHAINFILENAME);
		exit (1);
	}

	memset(&rb,0,sizeof(rb));
	rb.AgentID				= agentID;
	rb.UserDefined			= CMD_INITKEYGEN;
	printf ("Generating keys on card...\n");
	if ((rc = _sccRequest(handle,&rb)) != 0)
	{
		printf("sccRequest failed rc = 0x%x\n",rc);
		sccCloseAdapter(handle);
		exit(1);
	}
	if (rb.Status != 0)
	{
		printf ("Error, status returned is %d\n", rb.Status);
		exit (2);
	}
	printf ("Card initialized successfully!\n");
	printf ("Getting cert chain...\n");
	memset(&rb,0,sizeof(rb));
	rb.AgentID				= agentID;
	rb.InBufferLength[0]	= sizeof(bigbuf);
	rb.pInBuffer[0]			= (void *)bigbuf;
	rb.UserDefined			= CMD_GETCHAIN;
	if ((rc = _sccRequest(handle,&rb)) != 0)
	{
		printf("sccRequest failed rc = 0x%x\n",rc);
		sccCloseAdapter(handle);
		exit(1);
	}
	if (rb.Status != 0)
	{
		printf ("Error, status returned is %d\n", rb.Status);
		exit (2);
	}
	fwrite (bigbuf, 1, rb.InBufferLength[0], fchain);
	fclose (fchain);
	chainlen = rb.InBufferLength[0];
	memcpy (chainbuf, bigbuf, chainlen);
	printf ("Cert chain retrieved.\n");

	return 0;
}

static int
dorollover (int dbnum)
{
	long				rc;
	FILE				*fchain;
	dbproof				*db;
	int					dbcreated;

	db = opendb (dbname (dbnum), &dbcreated);
	if (!dbcreated)
	{
		fprintf (stderr, "Rollover error, old database file %s found.\n",
					dbname(dbnum));
		exit (1);
	}

	if ((fchain = fopen (CHAINFILENAME, "wb")) == NULL)
	{
		fprintf (stderr, "Unable to open chain file %s for output\n", CHAINFILENAME);
		exit (1);
	}
	memset(&rb,0,sizeof(rb));
	rb.AgentID				= agentID;
	rb.UserDefined			= CMD_ROLLOVER;
	rb.OutBufferLength[0]	= sizeof(dbnum);
	rb.pOutBuffer[0]		= (unsigned char *) &dbnum;
	printf ("Generating rollover keys on card as number %d...\n", dbnum);
	if ((rc = _sccRequest(handle,&rb)) != 0)
	{
		printf("sccRequest failed rc = 0x%x\n",rc);
		sccCloseAdapter(handle);
		exit(1);
	}
	if (rb.Status != 0)
	{
		printf ("Error, status returned is %d\n", rb.Status);
		exit (2);
	}
	printf ("Rollover keys generated successfully!\n");
	printf ("Getting new cert chain...\n");
	memset(&rb,0,sizeof(rb));
	rb.AgentID             = agentID;
	rb.InBufferLength[0]  = sizeof(bigbuf);
	rb.pInBuffer[0]       = (void *)bigbuf;
	rb.UserDefined         = CMD_GETCHAIN;
	if ((rc = _sccRequest(handle,&rb)) != 0)
	{
		printf("sccRequest failed rc = 0x%x\n",rc);
		sccCloseAdapter(handle);
		exit(1);
	}
	if (rb.Status != 0)
	{
		printf ("Error, status returned is %d\n", rb.Status);
		exit (2);
	}
	fwrite (bigbuf, 1, rb.InBufferLength[0], fchain);
	fclose (fchain);
	chainlen = rb.InBufferLength[0];
	memcpy (chainbuf, bigbuf, chainlen);
	printf ("Cert chain retrieved.\n");

	return 0;
}

static int
dolisten (int port, int numdbs)
{
	long				rc;
	char				*buf;
	unsigned short		buflen;
	unsigned long		statlen;
	int					found;
	unsigned char		*proof;
	unsigned 			prooflen;
	SOCKET				s, s1;
	unsigned char		cmd;
	struct sockaddr_in	sockaddr, otheraddr;
	int					otheraddrsize = sizeof(otheraddr);
	int					reuseflag = -1;
	unsigned char		roothashbuf[HASHSIZE];
	unsigned int		fileid;
	FILE				*fchain;
	dbproof				**db;
	int					dbcreated;
	int					i;
	unsigned			status;
	time_t				curtime;
unsigned int debug3[100];

	/* Read certificate chain file for responding to requests */
	if ((fchain = fopen (CHAINFILENAME, "rb")) == NULL)
	{
		fprintf (stderr, "Unable to open chain file %s\n", CHAINFILENAME);
		exit (1);
	}
	chainlen = fread (chainbuf, 1, sizeof(bigbuf), fchain);
	fclose (fchain);

	/* Open DBs */
	db = malloc (numdbs * sizeof(dbproof *));
	for (i=0; i<numdbs; i++)
	{
		db[i] = opendb (dbname(i), &dbcreated);
		if (dbcreated)
		{
			fprintf (stderr, "Unable to find DB file %s; delete it and run keygen\n", dbname(i));
			exit (1);
		}
	}

#if !defined(_WIN32)
	signal (SIGALRM, alarmhandler);
#endif

	/* Begin listening on socket */
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror ("socket");
		exit (2);
	}
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons((short)port);
	sockaddr.sin_addr.s_addr = INADDR_ANY;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuseflag, sizeof(reuseflag));
	if (bind (s, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		perror ("bind");
		exit (2);
	}
	if (listen(s, 5) < 0) {
		perror ("listen");
		exit (2);
	}

	printf ("Listening on port %d, %d rpowdb files found...\n", port, numdbs);

	for ( ; ; )
	{
		/* Handle commands */
		s1 = accept (s, (struct sockaddr *)&otheraddr, &otheraddrsize);
		if (s1 < 0) {
			perror ("accept");
			exit (2);
		}
		printf ("Incoming connection from ");
		printf ("%d.%d.%d.%d at ", otheraddr.sin_addr.s_addr&0xff,
						(otheraddr.sin_addr.s_addr>>8)&0xff,
						(otheraddr.sin_addr.s_addr>>16)&0xff,
						(otheraddr.sin_addr.s_addr>>24)&0xff);
		curtime = time(NULL);
		printf ("%s", ctime(&curtime));
		

		if (nread (s1, &cmd, 1) < 1
			|| nread (s1, &buflen, 2) < 2)
		{
			close (s1);
			continue;
		}
		buflen = ntohs (buflen);
		buf = malloc (buflen);
		if (nread (s1, buf, buflen) < buflen)
		{
			free (buf);
			close (s1);
			continue;
		}

		switch (cmd)
		{
		case CMD_GETCHAIN:
			free (buf);
			buflen = htons ((short)chainlen);
			send (s1, (unsigned char *)&buflen, 2, 0);
			send (s1, chainbuf, UP4(chainlen), 0);
			close (s1);
			printf ("Chain query answered\n");
			break;
		case CMD_STAT:
			if (buflen != KEYSIZE/8)
			{
				free (buf);
				close (s1);
				break;
			}

			memset (&rb, 0, sizeof(rb));
			rb.AgentID				= agentID;
			rb.OutBufferLength[0]	= KEYSIZE / 8;
			rb.pOutBuffer[0]		= buf;
			rb.InBufferLength[0]	= sizeof(bigbuf);
			rb.pInBuffer[0]			= bigbuf;
			rb.UserDefined			= CMD_STAT;

			if ((rc = _sccRequest(handle,&rb)) != 0)
			{
				printf("sccRequest failed rc = 0x%x\n",rc);
				sccCloseAdapter(handle);
				exit(1);
			}
			free (buf);
			status = htonl (rb.Status);
			send (s1, (unsigned char *)&status, sizeof(status), 0);

			if (rb.Status != 0)
			{
				printf ("Card reports error, code is %d\n", rb.Status);
				close (s1);
				continue;
			}

			/* Return reply to the client */
			send (s1, bigbuf, rb.InBufferLength[0], 0);
			close (s1);
			printf ("Status query answered\n");
			break;
		case CMD_SIGN:
			if ((buflen-CARDID_LENGTH) <= KEYSIZE/8
					||  (buflen-CARDID_LENGTH) % 4 != 0)
			{
				free (buf);
				close (s1);
				break;
			}
#if 0
			msgcardid = buf;
			if (memcmp (msgcardid, cardid, CARDID_LENGTH) != 0)
			{
				free (buf);
				status = htonl (RPOW_STAT_BADCARDID);
				send (s1, (unsigned char *)&status, sizeof(status), 0);
				close (s1);
				break;
			}
#endif
			memset (&rb, 0, sizeof(rb));
			rb.AgentID				= agentID;
			rb.OutBufferLength[0]	= KEYSIZE / 8;
			rb.pOutBuffer[0]		= buf + CARDID_LENGTH;
			rb.OutBufferLength[1]	= buflen - (KEYSIZE / 8) - CARDID_LENGTH;
			rb.pOutBuffer[1]		= buf + (KEYSIZE / 8) + CARDID_LENGTH;
			rb.InBufferLength[0]	= sizeof(bigbuf);
			rb.pInBuffer[0]			= bigbuf;
			rb.InBufferLength[1]	= sizeof(roothashbuf);
			rb.pInBuffer[1]			= roothashbuf;
			rb.InBufferLength[2]	= sizeof(fileid);
			rb.pInBuffer[2]			= &fileid;
			rb.UserDefined			= CMD_SIGN;
rb.InBufferLength[3] = sizeof(debug3);		// holds profile timing
rb.pInBuffer[3] = (unsigned char *)debug3;

			blocksigs (BLOCK);

			if ((rc = _sccRequest(handle,&rb)) != 0)
			{
				printf("sccRequest failed rc = 0x%x\n",rc);
				sccCloseAdapter(handle);
				exit(1);
			}
			free (buf);

			/* Handle database queries from card */
			while (rb.Status == -ERR_DBQUERY)
			{
				/* We expect to get a hash back */
				if (rb.InBufferLength[0] != HASHSIZE)
				{
					printf ("Error, answer back length is %d\n",
							rb.InBufferLength[0]);
					exit (2);
				}

				/* Now we query our database to see if the item is present */
				if (fileid >= numdbs)
				{
					printf ("Error, card asked for fileid %d\n", fileid);
					prooflen = 0;
					proof = NULL;
					found = 1;
				} else {
printf ("Host querying DB %d with hash ", fileid);
dumpbuf (bigbuf, HASHSIZE);
printf ("Host expects DB root hash ");
dumpbuf (roothashbuf, HASHSIZE);
					found = testdbandset (db[fileid], &proof, &prooflen, bigbuf);
				}

				/* Send the proof */
				memset (&rb, 0, sizeof(rb));
				rb.AgentID				= agentID;
				rb.OutBufferLength[0]	= sizeof(prooflen);
				rb.pOutBuffer[0]		= &prooflen;
				rb.OutBufferLength[1]	= UP4(prooflen);
				rb.pOutBuffer[1]		= proof;

				/* Get back the card's official answer */
				rb.InBufferLength[0]	= sizeof(bigbuf);
				rb.pInBuffer[0]			= bigbuf;
				rb.InBufferLength[1]	= sizeof(roothashbuf);
				rb.pInBuffer[1]			= roothashbuf;
				rb.InBufferLength[2]	= sizeof(fileid);
				rb.pInBuffer[2]			= &fileid;
rb.InBufferLength[3] = sizeof(debug3);		// holds profile timing
rb.pInBuffer[3] = (unsigned char *)debug3;
				rb.UserDefined			= CMD_DBAUTH;
				
				if ((rc = _sccRequest(handle,&rb)) != 0)
				{
					printf("sccRequest failed rc = 0x%x\n",rc);
					sccCloseAdapter(handle);
					exit(1);
				}
			}

			blocksigs (UNBLOCK);

			/* Send card status preceding reply message if any */
			status = htonl (rb.Status);
			send (s1, (unsigned char *)&status, sizeof(status), 0);

			if (rb.Status != 0)
			{
				printf ("Card reports error, code is %d\n", rb.Status);
				close (s1);
				continue;
			}

			/* Return reply to the client */
			send (s1, bigbuf, rb.InBufferLength[0], 0);
			close (s1);
			printf ("Sign request handled\n");
			break;
		default:
			free (buf);
			close (s1);
			break;
		}
		fflush (stdout);
	}

	/* never gets here */

	if ((rc = sccCloseAdapter(handle)) != 0)
	{
		printf("sccCloseAdapter failed rc = 0x%x\n",rc);
		exit(1);
	}

}


void
dumpbuf (unsigned char *buf, int len)
{
	int i;
	int off = 0;

	for (i=0; i<len; i++)
	{
#if 0
		if (i%16 == 0) {
			printf ("%04x  ", off);
			off += 16;
		}
#endif
//		printf ("%02x%s", buf[i], ((i+1)%16 == 0) ? "\n" : " ");
		printf ("%02x ", buf[i]);
	}
	if (len%16 != 0)
		printf ("\n");
}


/* Read until we reach count bytes, or error */
static int
nread (int fd, void *buf, unsigned count)
{
	unsigned char *cbuf = buf;
	int err, nr = 0;

	while (nr < count)
	{
		alarm (TIMEOUTSECS);
		alarmflag = 0;
		err = recv (fd, cbuf+nr, count-nr, 0);
		alarm (0);
		if (alarmflag || err <= 0)
			return nr;
		nr += err;
	}
	return nr;
}

#if 0
static int
dostat ()
{
	unsigned char debug0[10000], debug1[10000];
	unsigned long debug2[2];
	long rc;

	memset (&rb, 0, sizeof(rb));
	rb.AgentID				= agentID;
	rb.InBufferLength[0] = sizeof(debug0);
	rb.pInBuffer[0] = debug0;
	rb.InBufferLength[1] = sizeof(debug1);
	rb.pInBuffer[1] = debug1;
	rb.InBufferLength[2] = sizeof(debug2);
	rb.pInBuffer[2] = (unsigned char *)debug2;
	rb.UserDefined			= CMD_STAT;

	if ((rc = _sccRequest(handle,&rb)) != 0)
	{
		printf("sccRequest failed rc = 0x%x\n",rc);
		sccCloseAdapter(handle);
		exit(1);
	}
	if (rb.Status != 0)
	{
		printf ("Error, status returned is %d\n", rb.Status);
		exit (2);
	}

	printf ("Card status results:\n");
	printf ("GetConfig:\n");
	dumpbuf (debug0, rb.InBufferLength[0]);
	printf ("OAStatus:\n");
	dumpbuf (debug1, rb.InBufferLength[1]);
	printf ("PPD space: Flash: %d, BBRAM: %d\n", debug2[0], debug2[1]);
	return 0;
}
#endif

long SCC_CALL
_sccRequest(sccAdapterHandle_t  adapter_handle,
					 sccRB_t            *request_block)
{
	long rc;
	char dbuf[2048];
	sccRB_t rb1;

	memcpy (&rb1, request_block, sizeof (rb1));
	for ( ; ; )
	{
		memcpy (request_block, &rb1, sizeof (rb1));
		request_block->InBufferLength[3] = sizeof(dbuf);
		request_block->pInBuffer[3] = dbuf;
		
		rc = sccRequest (adapter_handle, request_block);
		if (rc != 0)
			return rc;
		if (request_block->Status != 123 && request_block->Status != 124)
			return rc;
		if (request_block->Status == 123)
		{
			printf ("Msg from card: %s", dbuf);
			fflush (stdout);
		}
		else if (request_block->Status == 124)
		{
			printf ("Buf from card:\n");
			dumpbuf (dbuf, request_block->InBufferLength[3]);
		}
	}
}

static void
inthandler (int signum)
{
	signal (signum, SIG_IGN);
	interruptflag = 1;
}

static void
alarmhandler (int signum)
{
	alarmflag = 1;
	printf ("(timed out)\n");
}

/* Block or unblock signals */
static void
blocksigs (int blockflag)
{
	if (blockflag)
	{
		signal (SIGINT, inthandler);
		signal (SIGTERM, inthandler);
	} else {
		if (interruptflag)
		{
			printf ("Interrupted by signal, exiting...\n");
			exit (0);
		}
		signal (SIGINT, SIG_DFL);
		signal (SIGTERM, SIG_DFL);
	}
}
