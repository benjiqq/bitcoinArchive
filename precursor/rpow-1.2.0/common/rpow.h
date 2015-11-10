/*
 * rpow.h
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

#ifndef RPOW_H
#define RPOW_H

#include "commands.h"
#include "errors.h"

#define DEFAGENT  \
	static sccAgentID_t agentID = {{'\0','\0'}, \
                              {'r','e','u','s','a','b','l','e','p','o','w'}, \
                              {'\0'}, \
                              {'\0'}, \
                              {'\0'}}


#define UP4(n)	((((n)+3)/4)*4)

/* Our hashcash resource string, preceded by cardid in hex */
#define POW_RESOURCE_TAIL		".rpow.net"


/*
 * Exponent used for all rpow keys; signing keys use consecutive
 * primes starting from here.
 */
#define RPOW_EXP		65537


#define RPOW_TYPE_RPOW		1
#define RPOW_TYPE_HASHCASH	2

/* Status codes */
#define RPOW_STAT_OK			0
#define RPOW_STAT_REUSED		1
#define RPOW_STAT_INVALID		2
#define RPOW_STAT_INSUFFICIENT	3
#define RPOW_STAT_BADTIME		4
#define RPOW_STAT_MISMATCH		5
#define RPOW_STAT_WRONGKEY		6
#define RPOW_STAT_BADFORMAT		7
#define RPOW_STAT_BADRESOURCE	8
#define RPOW_STAT_UNKNOWNKEY	9
#define RPOW_STAT_BADRPEND		10
#define RPOW_STAT_BADCARDID		11

#define KEYID_LENGTH	20
#define CARDID_LENGTH	14
#define RPOW_ID_LENGTH	(20+CARDID_LENGTH)

#define RPOW_VALUE_MIN	20
#define RPOW_VALUE_MAX	50
#define RPOW_VALUE_COUNT (RPOW_VALUE_MAX-RPOW_VALUE_MIN+1)

#endif
