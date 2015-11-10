/*
 * rpio.c
 *	Low level I/O for rpow package
 */

#include "rpowscc.h"


rpowio *
rp_new  ()
{
	rpowio *rp = malloc (sizeof(rpowio));
	memset (rp, 0, sizeof (rpowio));
	rp->buf = malloc (1);
	return rp;
}

rpowio *
rp_new_from_buf  (unsigned char *buf, unsigned len)
{
	rpowio *rp = malloc (sizeof(rpowio));
	memset (rp, 0, sizeof (rpowio));
	rp->buf = malloc(len);
	if (rp->buf == NULL)
	{
		free (rp);
		return NULL;
	}
	memcpy (rp->buf, buf, len);
	rp->len = len;
	return rp;
}

rpowio *
rp_new_from_malloc_buf  (unsigned char *buf, unsigned len)
{
	rpowio *rp = malloc (sizeof(rpowio));
	memset (rp, 0, sizeof (rpowio));
	rp->buf = buf;
	rp->len = len;
	return rp;
}

unsigned char *
rp_buf (rpowio *rp, unsigned *len)
{
	if (len)
		*len = rp->off;
	return rp->buf;
}

void
rp_free (rpowio *rp)
{
	if (rp->buf)
		free (rp->buf);
	free (rp);
}

int
rp_write (rpowio *rp, void *buf, unsigned len)
{
	if (rp->off + len > rp->len)
	{
		rp->buf = realloc (rp->buf, 2*(rp->off + len));
		if (rp->buf == NULL)
			return -1;
		rp->len = 2*(rp->off + len);
	}
	memcpy (rp->buf+rp->off, buf, len);
	rp->off += len;
	return len;
}

int
rp_read (rpowio *rp, void *buf, unsigned len)
{
	int rlen = rp->len - rp->off;

	rlen = (len < rlen) ? len : rlen;
	memcpy (buf, rp->buf+rp->off, rlen);
	rp->off += rlen;
	return rlen;
}


/* gbignum I/O */

int
bnwrite (gbignum *bn, rpowio *rpio)
{
	unsigned char *p;
	int len;
	int nlen;

	len = gbig_buflen (bn);
	p = malloc (len);
	gbig_to_buf (p, bn);
	nlen = ntohl(len);
	if (rp_write (rpio, &nlen, sizeof(nlen)) != sizeof(nlen)
			|| rp_write (rpio, p, len) != len)
	{
		free (p);
		return -1;
	}
	free (p);
	return 0;
}

int
bnread (gbignum *bn, rpowio *rpio)
{
	unsigned char *p;
	unsigned len;

	if (rp_read (rpio, &len, 4) != 4)
		return -1;
	len = ntohl(len);
	if (len > 2048/8)		/* Limit size of data we try to read */
		return -1;

	p = malloc (len);
	if (p==NULL)
		return -1;
	if (rp_read (rpio, p, len) != len)
	{
		free (p);
		return -1;
	}
	gbig_from_buf (bn, p, len);
	free (p);
	return 0;
}

int
pubkey_read (pubkey *pk, rpowio *rpio)
{
	int rc;
	memset (pk, 0, sizeof(pubkey));
	if ((rc = bnread (&pk->n, rpio)) != 0)
		return rc;
	if ((rc = bnread (&pk->e, rpio)) != 0)
		return rc;
	if (rp_read (rpio, pk->keyid, KEYID_LENGTH) != KEYID_LENGTH)
		return -1;
	if (rp_read (rpio, &pk->state, sizeof(pk->state)) != sizeof(pk->state))
		return -1;
	if (rp_read (rpio, &pk->fileid, sizeof(pk->fileid)) != sizeof(pk->fileid))
		return -1;
	return 0;
}

int
pubkey_write (pubkey *pk, rpowio *rpio)
{
	int rc;
	if ((rc = bnwrite (&pk->n, rpio)) != 0)
		return rc;
	if ((rc = bnwrite (&pk->e, rpio)) != 0)
		return rc;
	if (rp_write (rpio, pk->keyid, KEYID_LENGTH) != KEYID_LENGTH)
		return -1;
	if (rp_write (rpio, &pk->state, sizeof(pk->state)) != sizeof(pk->state))
		return -1;
	if (rp_write (rpio, &pk->fileid, sizeof(pk->fileid)) != sizeof(pk->fileid))
		return -1;
	return 0;
}
