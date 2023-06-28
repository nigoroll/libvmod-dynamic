/*-
 * Copyright 2019 UPLEX - Nils Goroll Systemoptimierung
 * All rights reserved.
 *
 * Authors: Nils Goroll <nils.goroll@uplex.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

// additional interfaces between vmod and getdns

#include "getdns/getdns.h"

//EXTENSION
#define GETDNS_RETURN_NO_SERVBYNAME -2
#define GETDNS_RETURN_NO_ANSWERS -3

struct VPFX(dynamic_resolver);

struct VPFX(dynamic_resolver_context) {
	unsigned					magic;
#define DYNAMIC_RESOLVER_CONTEXT_MAGIC			0x01631d25
	VSLIST_ENTRY(VPFX(dynamic_resolver_context))	list;
	getdns_context					*context;
	struct VPFX(dynamic_resolver)			*resolver;
};

struct VPFX(dynamic_resolver) {
	unsigned					magic;
#define DYNAMIC_RESOLVER_MAGIC				0x00631d25
	int						n_contexts;
	char						*vcl_name;
	VSLIST_HEAD(,VPFX(dynamic_resolver_context))	contexts;
	pthread_mutex_t				mtx;
	pthread_cond_t					cond;
	struct VPFX(dynamic_resolver_context)		*freeptr;
};

const char * dyn_getdns_strerror(int);

struct VPFX(dynamic_resolver_context) * dyn_getdns_get_context(struct VPFX(dynamic_resolver) *r);
void dyn_getdns_rel_context(struct VPFX(dynamic_resolver_context) **cp);
