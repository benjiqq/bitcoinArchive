/*
 * errors.h
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

#ifndef ERRORS_H
#define ERRORS_H

#define ERR_UNKNOWNCMD			(-1)
#define ERR_BADINPUT			(-2)
#define ERR_NOMEM				(-3)
#define ERR_INVALID				(-4)
#define ERR_DBFAILED			(-5)
#define ERR_UNINITIALIZED		(-6)

#define ERR_FAILEDOTHER			(-20)
#define ERR_FAILEDPUTBUFFER		(-21)
#define ERR_FAILEDGETBUFFER		(-22)
#define ERR_FAILEDGENERATE		(-23)
#define ERR_FAILEDGETCERT		(-24)
#define ERR_FAILEDSHA1			(-25)
#define ERR_FAILEDRSADECRYPT	(-26)
#define ERR_FAILEDRSAENCRYPT	(-27)
#define ERR_FAILEDRSASIGN		(-28)
#define ERR_FAILEDTDESDECRYPT	(-29)
#define ERR_FAILEDTDESENCRYPT	(-30)
#define ERR_FAILEDPPD			(-31)
#define ERR_FAILEDOA			(-32)
#define ERR_FAILEDBLIND			(-33)

/* Not an error, but a database query */
#define ERR_DBQUERY				(-100)

#endif
