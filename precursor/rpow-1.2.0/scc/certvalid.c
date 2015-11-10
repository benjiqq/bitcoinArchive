/*
 * certvalid.c
 * Validate a 4758 certificate chain.
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
#include <string.h>
#include <scctypes.h>
#include <scc_oa.h>

#include "rpowscc.h"

/* Version 2.31 of the 4758 OS, "CCA 2.31 & PKCS#11 Segment-2" */
static unsigned char oshash231[] = {
    0xee, 0xd7, 0xa0, 0x73, 0xa9, 0xd6, 0x0c, 0x04,
    0x57, 0x23, 0x82, 0x78, 0x87, 0x72, 0x27, 0x6b,
    0x99, 0xdd, 0xc8, 0xa0
};
/* Version 2.41-2.42 of the 4758 OS, "2.41 CP/Q++" */
static unsigned char oshash241[] = {
    0x4d, 0xb7, 0x7c, 0x4e, 0x47, 0x92, 0xe3, 0xd5,
    0xbc, 0x4a, 0x48, 0xed, 0x0f, 0x40, 0xde, 0x42,
    0x69, 0x8e, 0xbb, 0x30
};



static int certvalidatelayer (unsigned long *certlen, int *type,
	sccOA_CKO_Name_t *name, unsigned char *md1, unsigned char *md2,
	unsigned char *md3, unsigned char *certbuf, unsigned long certbuflen);

static int checkclass (unsigned char *cert, unsigned long certlen,
	sccOA_CKO_Name_t *name);

static int layertomd (unsigned char *md, unsigned long *owner,
	unsigned char *buf, unsigned buflen, var_t *var);

/*
 * Validate the cert chain starting at certbuf.  Return 0 if OK.
 *
 * We require the cert to substantially match our own certification
 * chain: same application hash, one of two different OS hashes,
 * same miniboot hash.  And the OA key must be a configuration
 * key rather than an epoch key, because configuration keys are
 * volatile and will evaporate if the program is reloaded.  Of
 * course, if the hashes match then it should be axiomatic that
 * the OA key is legal, since we don't create epoch keys.
 *
 * Return nonzero on validation error.
 *
 * On success, returns these output pointers:
 * innerbuf, points within the certbuf at a block of data which can be
 *   embedded by the application in the final key in the chain.
 * innerbuflen, the length of innerbuf.
 */
int
certvalidate ( unsigned char **innerbuf, unsigned long *innerbuflen,
	unsigned char *certbuf, unsigned long certbuflen,
	sccOA_CKO_Name_t *mycertname)
{
	sccOA_CKO_Head_t	*head;
	sccOA_CKO_Body_t	*body;
	sccOA_CKO_Name_t	name;
	int					type;
	unsigned			off;
	unsigned			len;
	unsigned char		*mycertbuf;
	unsigned long		mycertbuflen;
	unsigned long		topcertlen;
	unsigned char		md1[SHA1_DIGEST_LENGTH];
	unsigned char		md2[SHA1_DIGEST_LENGTH];
	unsigned char		md3[SHA1_DIGEST_LENGTH];
	unsigned char		mymd1[SHA1_DIGEST_LENGTH];
	unsigned char		mymd3[SHA1_DIGEST_LENGTH];
	int					stat;

	/* Read my own cert to get my message digest */
	if ((stat = getcertchain (&mycertbuf, &mycertbuflen, mycertname)) != 0)
		goto error;

	(void)certvalidatelayer (&topcertlen, &type, &name, mymd1, md2, mymd3,
			mycertbuf, mycertbuflen);
	free (mycertbuf);

	stat = certvalidatelayer (&topcertlen, &type, &name, md1, md2, md3,
			certbuf, certbuflen);

	if (stat != 0)
		goto done;

	if (type != OA_CKO_SEG3_CONFIG)
		goto error;

	/* Validate message hashes to see that it matches this card */
	if (memcmp (md1, mymd1, SHA1_DIGEST_LENGTH) != 0)
		goto error;

	if (memcmp (md2, oshash231, SHA1_DIGEST_LENGTH) != 0
			&& memcmp (md2, oshash241, SHA1_DIGEST_LENGTH) != 0)
		goto error;

	if (memcmp (md3, mymd3, SHA1_DIGEST_LENGTH) != 0)
		goto error;

	/* Success! */

	if (innerbuf != NULL)
	{
		head = (sccOA_CKO_Head_t *) certbuf;
		off = head->vData.offset;
		body = (sccOA_CKO_Body_t *)(((unsigned char *)&head->vData) + off);
		off = body->vDescB.offset;
		len = body->vDescB.len;
		*innerbuf = ((unsigned char *)&body->vDescB) + off;
		if (innerbuflen)
			*innerbuflen = len;
	}

	stat = 0;
	goto done;
error:
	stat = -1;
done:
	return stat;
}


/* Returns success == 0, nonzero on failure */
static int
certvalidatelayer (unsigned long *certlen, int *type, sccOA_CKO_Name_t *name,
	unsigned char *md1, unsigned char *md2, unsigned char *md3,
	unsigned char *certbuf, unsigned long certbuflen)
{
	sccOA_CKO_Head_t	*head;
	sccOA_CKO_Body_t	*body;
	unsigned			bodylen;
	unsigned char		*sig;
	unsigned			siglen;
	unsigned char		*parentcertbuf;
	unsigned			parentcertbuflen;
	unsigned long		parentcertlen;
	sccOA_CKO_Name_t	parentname;
	int					parenttype;
	unsigned long		certtype;
	unsigned long		osowner;
	unsigned			off;
	int					stat;
	unsigned long		otSig;

	if (certbuflen < 4)
	{	
		*certlen = 0;
		*type = 0;
		memset (name, 0, sizeof(*name));
		name->name_type = OA_IBM_ROOT;
		return 0;
	}

	head = (sccOA_CKO_Head_t *) certbuf;
	if (sizeof(*head) > certbuflen)
		goto error;
	if (head->struct_id.name != SCCOA_CKO_HEAD_T)
		goto error;
	if (head->struct_id.version != SCCOA_CKO_HEAD_VER)
		goto error;
	off = head->vData.offset;
	body = (sccOA_CKO_Body_t *)(((unsigned char *)&head->vData) + off);
	bodylen = head->vData.len;
	if ((unsigned char *)body - certbuf + sizeof(*body) > certbuflen)
		goto error;
	if ((unsigned char *)body - certbuf + bodylen > certbuflen)
		goto error;
	if (body->struct_id.name != SCCOA_CKO_BODY_T)
		goto error;
	if (body->struct_id.version != SCCOA_CKO_BODY_VER)
		goto error;
	if (body->tPublic != OA_RSA)
	{
		stat = -2;			/* Unsupported */
		goto done;
	}

	off = head->vSig.offset;
	sig = ((unsigned char *)&head->vSig) + off;
	siglen = head->vSig.len;
	if (sig-certbuf + siglen > certbuflen)
		goto error;

	*certlen = sig + siglen - certbuf;
	parentcertbuf = sig + siglen;
	parentcertbuflen = certbuf + certbuflen - parentcertbuf;
	stat = certvalidatelayer (&parentcertlen, &parenttype, &parentname,
		md1, md2, md3, parentcertbuf, parentcertbuflen);
	if (stat < 0)
		goto done;

	/* Chain below us is OK.  Check our sig. */
	if (memcmp (&body->parent_name, &parentname, sizeof(parentname)) != 0)
		goto error;

	/* If parent is root, check that class cert matches, else validate sig */
	if (parentcertlen == 0)
		stat = checkclass (certbuf, *certlen, &body->cko_name);
	else
	{
		/* Cannot verify if tSig == 1, but works OK to change it! */
		otSig = head->tSig;
		head->tSig = 0;
		stat = sccOAVerify (parentcertbuf, parentcertlen, certbuf, *certlen);
		head->tSig = otSig;
	}
	if (stat != 0)
		goto done;

	/* Signature verifies OK */
	*type = certtype = body->cko_type;
	*name = body->cko_name;

	switch (certtype)
	{
	case OA_CKO_IBM_ROOT:
		/* Actually a class root */
		if (parenttype != 0)
			goto error;
		break;
	case OA_CKO_MB: if (parenttype != OA_CKO_IBM_ROOT &&
				parenttype != OA_CKO_MB)
			goto error;
		stat = layertomd (md1, NULL, certbuf, certbuflen, &body->vDescB);
		if (stat < 0)
			goto done;
		break;
	case OA_CKO_SEG2_SEG3:
		if (parenttype != OA_CKO_MB)
			goto error;
		stat = layertomd (md2, &osowner, certbuf, certbuflen, &body->vDescA);
		if (stat < 0)
			goto done;
		stat = layertomd (md3, NULL, certbuf, certbuflen, &body->vDescB);
		if (stat < 0)
			goto done;
		/* Require the OS to be the production or development owner */
		if (osowner != 2 && osowner != 3)
			goto error;
		break;
	case OA_CKO_SEG3_CONFIG:
	case OA_CKO_SEG3_EPOCH:
		if (parenttype != OA_CKO_SEG2_SEG3)
			goto error;
		break;
	default:
		goto error;
	}

	/* Everything looks OK at this level */
	stat = 0;
	goto done;

error:
	stat = -1;
done:
	return stat;
}

/*
 * Given the last cert in the chain, supposedly a class root cert,
 * verify that it matches our class root.
 */
static int
checkclass (unsigned char *cert, unsigned long certlen,
	sccOA_CKO_Name_t *name)
{
	long				rc;
	unsigned char		*buf;
	unsigned long		buflen = 0;
	int					ok;

	if ((rc = sccOAGetCert (name, NULL, &buflen)) != 0)
		return -1;
	if (buflen != certlen)
		return -1;
	buf = malloc (buflen);
	if (buf == NULL)
		return -1;
	sccOAGetCert (name, buf, &buflen);
	ok = (memcmp (cert, buf, certlen) == 0);
	free (buf);
	return (ok ? 0 : -1);
}


/* Check a pointer to a layer descriptor and pull out the message digest */
static int
layertomd (unsigned char *md, unsigned long *owner,
	unsigned char *buf, unsigned buflen, var_t *var)
{
	unsigned off = var->offset;
	unsigned char *layerbuf = (unsigned char *)var + off;
	sccOALayerDesc_t *layerdesc = (sccOALayerDesc_t *)layerbuf;
	unsigned len = var->len;

	if (layerbuf + len > buf + buflen)
		return -1;

	if (layerdesc->struct_id.name != SCCOALAYERDESC_T)
		return -1;
	if (layerdesc->struct_id.version != SCCOALAYERDESC_VER)
		return -1;
	memcpy (md, layerdesc->image_hash, sizeof(layerdesc->image_hash));
	if (owner)
		*owner = layerdesc->ownerID;
	return 0;
}
