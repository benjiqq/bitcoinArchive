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
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "scc.h"
#include "util4758.h"
#include "certvalid.h"

static unsigned char rootmod[] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	0x0c, 0xac, 0xba, 0xed, 0xfc, 0xeb, 0x4a, 0x2d,
	0x1f, 0xce, 0x8b, 0x0f, 0x42, 0xaa, 0x10, 0xde,
	0xb9, 0x40, 0x56, 0x85, 0xc8, 0x00, 0x15, 0x6c,
	0x00, 0x0d, 0x46, 0x35, 0x81, 0x1f, 0x34, 0xd4,
	0x37, 0x5f, 0x17, 0xf0, 0x34, 0x45, 0xec, 0x7b,
	0xc2, 0x51, 0x61, 0x82, 0x20, 0xf7, 0x53, 0x91,
	0xd0, 0xf9, 0x1f, 0xe6, 0xaa, 0x52, 0xca, 0x9a,
	0x46, 0x3f, 0xe8, 0x7b, 0xf7, 0x8f, 0xf8, 0x42,
	0xa7, 0x70, 0xee, 0xc4, 0xb8, 0xb0, 0x7f, 0xd5,
	0x55, 0xbc, 0x54, 0xdf, 0x19, 0x4f, 0x3f, 0xc6,
	0xce, 0x1b, 0x49, 0x36, 0xee, 0x0b, 0xaa, 0x1e,
	0x4e, 0x7e, 0x6d, 0x57, 0x49, 0x4e, 0x83, 0x34,
	0x26, 0x18, 0x5c, 0xd3, 0x64, 0x40, 0xed, 0x2b,
	0x03, 0x96, 0x3d, 0xbc, 0x43, 0x2d, 0xf7, 0x17
};

/*
 * Acceptable class key moduli; these are for 4758-002
 * which is the high security version.
 * Note that the 04k9127v class key is a copy of
 * the 40h9952v file, although IBM suggests that they
 * are different.
 */
static unsigned char class40h9951v[] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
	0x9d, 0xce, 0xdf, 0xae, 0xd6, 0x49, 0xbe, 0x51,
	0xde, 0x64, 0x83, 0xb9, 0x84, 0x84, 0xfb, 0x82,
	0xfd, 0xfe, 0x73, 0x46, 0x74, 0xfa, 0xda, 0x40,
	0x81, 0xba, 0x41, 0x3b, 0xc0, 0x3f, 0x04, 0xd1,
	0x71, 0x41, 0x20, 0x27, 0xe2, 0xef, 0xd5, 0x2e,
	0x1e, 0xdb, 0x7b, 0xc7, 0x8a, 0x47, 0xd9, 0x6a,
	0xdc, 0x86, 0x2b, 0x9d, 0x36, 0x93, 0xdc, 0xb3,
	0x3d, 0xa1, 0x77, 0xc0, 0x9f, 0x56, 0xc4, 0xaa,
	0xc0, 0x5b, 0x5a, 0x9f, 0x67, 0x49, 0xd1, 0x21,
	0x8c, 0x95, 0x99, 0xf1, 0x8d, 0x7b, 0x16, 0x62,
	0x27, 0xd0, 0x91, 0xe3, 0x0a, 0x8a, 0x3e, 0x09,
	0x7b, 0xf0, 0xee, 0x51, 0xfd, 0xe9, 0x22, 0xb3,
	0x24, 0x9d, 0xe0, 0xe8, 0xce, 0x5c, 0x76, 0x40,
	0x1a, 0x9e, 0xfe, 0x84, 0x36, 0xf6, 0xdf, 0xa1,
};

static unsigned char class40h9952v[] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43,
	0x2d, 0x32, 0xb0, 0x00, 0xcd, 0x36, 0xda, 0x4e,
	0x91, 0x07, 0x97, 0xd5, 0xb2, 0x70, 0xc7, 0x9e,
	0x45, 0xec, 0x1e, 0xfb, 0xe1, 0x03, 0xcb, 0xe6,
	0x25, 0xde, 0x3e, 0x9c, 0xb5, 0xfb, 0xb1, 0xde,
	0x56, 0xd3, 0xd3, 0xec, 0x88, 0x14, 0xb3, 0x0a,
	0x4b, 0xcb, 0x7f, 0x94, 0x05, 0x2a, 0x6f, 0xd8,
	0x75, 0xed, 0xd5, 0xfb, 0xb3, 0xcc, 0x34, 0x28,
	0x0d, 0x02, 0x06, 0xed, 0x02, 0x86, 0x05, 0x29,
	0x43, 0x38, 0x1f, 0xf5, 0xf4, 0x9d, 0xc9, 0xff,
	0xb6, 0x4f, 0x61, 0x14, 0xd3, 0x91, 0x67, 0xe4,
	0x00, 0xf9, 0xa4, 0x37, 0xa2, 0xe8, 0xc7, 0xfa,
	0x9c, 0x80, 0xb4, 0x59, 0x03, 0xfb, 0x61, 0xb9,
	0x59, 0xcd, 0x7d, 0x3e, 0x75, 0x7e, 0x1c, 0x6b,
	0xba, 0x3a, 0xbd, 0xb6, 0x13, 0x0a, 0x10, 0x79,
};

#define NCLASSKEYS (sizeof(classkeys) / sizeof (classkeys[0]))
static unsigned char *classkeys[] = {
	class40h9951v, class40h9952v
};

static unsigned char rootexp[] = {
	0x01, 0x00, 0x01
};

/* Used for ISO 9796 padding */
static unsigned char perm9796[] = {
	14, 3, 5, 8, 9, 4, 2, 15, 0, 13, 11, 6, 7, 10, 12, 1
};

static int certvalidatelayer (RSA **key, int *type,
	sccName_t *name, unsigned char *md1, unsigned char *md2,
	unsigned char *md3, unsigned char *certbuf, unsigned long certbuflen,
	FILE *fout);

static int layertomd (unsigned char *md, unsigned long *owner,
	unsigned char *buf, unsigned buflen, ptr_t *ptr);

static int sigcheck (RSA *key, unsigned char *data, unsigned datalen,
	unsigned char *sig, unsigned siglen);

static RSA * rootkey4758 ();

/*
 * Validate the cert chain starting at certbuf.  Return 0 if OK,
 * and set the three SHA-1 message digests for the three 4758
 * layers: miniboot, OS, and application.
 *
 * Pass fout non-null to get verbose progress reports to it.
 *
 * Return < 0 on validation error.
 *
 * On success, if these return pointers are non-null they get set:
 *
 * key, the OpenSSL format final RSA public key in the chain.
 * epochflag true for epoch keys, which persist across reloads, and
 *   false for configuration keys, which get cleared on reloads.
 * innerbuf, points within the certbuf at a block of data which can be
 *   embedded by the application in the final key in the chain.
 * innerbuflen, the length of innerbuf.
 */
int
certvalidate (RSA **key, int *epochflag,
	unsigned char **innerbuf, unsigned long *innerbuflen,
	unsigned char *md1, unsigned char *md2, unsigned char *md3,
	unsigned char *certbuf, unsigned long certbuflen, FILE *fout)
{
	sccHead_t			*head;
	sccBody_t			*body;
	sccName_t			name;
	RSA					*rsakey = NULL;
	int					type;
	unsigned			off;
	unsigned			len;
	int					stat;

	stat = certvalidatelayer (&rsakey, &type, &name, md1, md2, md3,
			certbuf, certbuflen, fout);

	if (stat < 0)
		goto done;

	if (type != CERT_SEG3_CONFIG &&
			type != CERT_SEG3_EPOCH)
		goto error;

	if (key)
	{
		*key = rsakey;
		rsakey = NULL;
	}

	if (epochflag)
		*epochflag = (type == CERT_SEG3_EPOCH);

	if (innerbuf != NULL)
	{
		head = (sccHead_t *) certbuf;
		off = scctohl(head->vData.off);
		body = (sccBody_t *)(((unsigned char *)&head->vData) + off);
		off = scctohl(body->vDescB.off);
		len = scctohl(body->vDescB.len);
		*innerbuf = ((unsigned char *)&body->vDescB) + off;
		if (innerbuflen)
			*innerbuflen = len;
	}

	stat = 0;
	goto done;
error:
	stat = -1;
done:
	if (rsakey)
		RSA_free (rsakey);
	return stat;
}


/* Returns success == 0, < 0 on failure */
static int
certvalidatelayer (RSA **key, int *type, sccName_t *name,
	unsigned char *md1, unsigned char *md2, unsigned char *md3,
	unsigned char *certbuf, unsigned long certbuflen, FILE *fout)
{
	sccHead_t			*head;
	sccBody_t			*body;
	unsigned			bodylen;
	unsigned char		*sig;
	unsigned			siglen;
	unsigned char		*keybuf;
	sccRSAKey_t			*keytoken;
	unsigned char		*parentcertbuf;
	unsigned			parentcertbuflen;
	RSA					*signkey = NULL;
	sccName_t			parentname;
	int					parenttype;
	unsigned long		certtype;
	unsigned long		osowner;
	unsigned			off;
	int					stat;
	int					i;

	if (certbuflen < 4)
	{	
		*key = rootkey4758();
		*type = 0;
		memset (name, 0, sizeof(*name));
		name->name_type = htosccs(CERT_IBM_ROOT);
		return 0;
	}

	head = (sccHead_t *) certbuf;
	if (sizeof(*head) > certbuflen)
		goto error;
	if (head->struct_id.name != SCCHEAD_T)
		goto error;
	if (head->struct_id.version != SCCHEAD_VER)
		goto error;
	off = scctohl(head->vData.off);
	body = (sccBody_t *)(((unsigned char *)&head->vData) + off);
	bodylen = scctohl(head->vData.len);
	if ((unsigned char *)body - certbuf + sizeof(*body) > certbuflen)
		goto error;
	if ((unsigned char *)body - certbuf + bodylen > certbuflen)
		goto error;
	if (body->struct_id.name != SCCBODY_T)
		goto error;
	if (body->struct_id.version != SCCBODY_VER)
		goto error;
	if (scctohl(body->tPublic) != KEYTYPE_RSA)
	{
		stat = -2;			/* Unsupported */
		goto done;
	}

	off = scctohl(head->vSig.off);
	sig = ((unsigned char *)&head->vSig) + off;
	siglen = scctohl(head->vSig.len);
	if (sig-certbuf + siglen > certbuflen)
		goto error;

	parentcertbuf = sig + siglen;
	parentcertbuflen = certbuf + certbuflen - parentcertbuf;
	stat = certvalidatelayer (&signkey, &parenttype, &parentname,
		md1, md2, md3, parentcertbuf, parentcertbuflen, fout);
	if (stat < 0)
		goto done;

	/* Chain below us is OK.  Check our sig. */
	if (memcmp (&body->parent_name, &parentname, sizeof(parentname)) != 0)
		goto error;
	stat = sigcheck (signkey, (unsigned char *)body, bodylen, sig, siglen);
	if (stat < 0)
		goto done;

	/* Signature verifies OK */
	*type = certtype = scctohl(body->cko_type);
	*name = body->cko_name;

	off = scctohl(body->vPublic.off);
	keybuf = ((unsigned char *)&body->vPublic) + off;
	keytoken = (sccRSAKey_t *)keybuf;
	*key = rsafrom4758 (keytoken);

	switch (certtype)
	{
	case CERT_CLASS_ROOT:
		if (parenttype != 0)
			goto error;
		/* Check class root key modulus against the ones we allow */
		if (scctohl(keytoken->n_Length) != sizeof (rootmod))
			goto error;
		for (i=0; i<NCLASSKEYS; i++)
		{
			off = scctohl(keytoken->n_Offset);
			if (memcmp (keybuf + off, classkeys[i],
						scctohl(keytoken->n_Length)) == 0)
				break;
		}
		if (i == NCLASSKEYS)
			goto error;
		if (fout)
			fprintf (fout, "IBM root key signature on class key validated\n");
		break;
	case CERT_MB:
		if (parenttype != CERT_CLASS_ROOT &&
				parenttype != CERT_MB)
			goto error;
		stat = layertomd (md1, NULL, certbuf, certbuflen, &body->vDescB);
		if (stat < 0)
			goto done;
		if (fout)
		{
			if (parenttype == CERT_CLASS_ROOT)
				fprintf (fout, "Class key signature on device key validated\n");
			else
				fprintf (fout, "Device key signature on miniboot key validated\n");
		}
		break;
	case CERT_SEG2_SEG3:
		if (parenttype != CERT_MB)
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
		if (fout)
			fprintf (fout, "Miniboot key signature on OS key validated\n");
		break;
	case CERT_SEG3_CONFIG:
	case CERT_SEG3_EPOCH:
		if (parenttype != CERT_SEG2_SEG3)
			goto error;
		if (fout)
			fprintf (fout, "OS key signature on application key validated\n");
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
	if (signkey)
		RSA_free (signkey);
	return stat;
}


/* Check a pointer to a layer descriptor and pull out the message digest */
static int
layertomd (unsigned char *md, unsigned long *owner,
	unsigned char *buf, unsigned buflen, ptr_t *ptr)
{
	unsigned off = scctohl(ptr->off);
	unsigned char *layerbuf = (unsigned char *)ptr + off;
	sccLayerDesc_t *layerdesc = (sccLayerDesc_t *)layerbuf;
	unsigned len = scctohl(ptr->len);

	if (layerbuf + len > buf + buflen)
		return -1;

	if (layerdesc->struct_id.name != SCCLAYERDESC_T)
		return -1;
	if (layerdesc->struct_id.version != SCCLAYERDESC_VER)
		return -1;
	memcpy (md, layerdesc->image_hash, SHA_DIGEST_LENGTH);
	if (owner)
		*owner = scctohl(layerdesc->ownerID);
	return 0;
}

static RSA *
rootkey4758 ()
{
	RSA		*rsa = RSA_new();

	rsa->n = BN_bin2bn (rootmod, sizeof(rootmod), NULL);
	rsa->e = BN_bin2bn (rootexp, sizeof(rootexp), NULL);
	return rsa;
}

/*
 * Verify the ISO 9796 signature used by IBM cert chains.  Return 0
 * if OK, < 0 on error.
 */
static int
sigcheck (RSA *key, unsigned char *data, unsigned datalen,
	unsigned char *sig, unsigned siglen)
{
	BIGNUM			*padhash = BN_new();
	BIGNUM			*bnsig = BN_new();
	BIGNUM			*sigexp = BN_new();
	BIGNUM			*sigexp1 = BN_new();
	BN_CTX			*bnctx = BN_CTX_new();
	unsigned char	md[SHA_DIGEST_LENGTH];
	unsigned char 	*padbuf;
	unsigned		modlen;
	int				mdoff;
	int				ok;
	int				i;

	SHA1 (data, datalen, md);

	modlen = RSA_size (key);
	padbuf = malloc(modlen);

	if (modlen % 4 != 0)
		return -2;		/* Padding won't work */

	for (i=0; i<modlen; i+=2)
	{
		mdoff = SHA_DIGEST_LENGTH - ((modlen/2) % SHA_DIGEST_LENGTH);
		mdoff = (mdoff + i/2) % SHA_DIGEST_LENGTH;
		padbuf[i] = (perm9796[md[mdoff]>>4]<<4) | perm9796[md[mdoff]&0xf];
		padbuf[i+1] = md[mdoff];
	}
	padbuf[0] = 0x40 | (padbuf[0] & 0x3f);
	padbuf[modlen-2*SHA_DIGEST_LENGTH] ^= 0x01;
	padbuf[modlen-1] = 0x06 | ((padbuf[modlen-1] & 0xf) << 4);

	BN_bin2bn (padbuf, modlen, padhash);

	BN_bin2bn (sig, siglen, bnsig);
	BN_mod_exp (sigexp, bnsig, key->e, key->n, bnctx);
	BN_sub (sigexp1, key->n, sigexp);

	ok = (BN_cmp (padhash, sigexp) == 0  ||  BN_cmp (padhash, sigexp1) == 0);

	BN_free (sigexp1);
	BN_free (sigexp);
	BN_free (bnsig);
	BN_free (padhash);
	BN_CTX_free (bnctx);

	return ok ? 0 : -1;
}
