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

#include "config.h"

#include <cache/cache.h>
#include <string.h>	// miniobj.h

#include "vcc_dynamic_if.h"
#include "dyn_getdns.h"
#include "getdns/getdns_extra.h"

const char *
dyn_getdns_strerror(int ra)
{
	const char *s;

	if (ra >= 0) {
		s = getdns_get_errorstr_by_id(ra);
		if (s != NULL)
			return (s);
	}
#define GETDNS_RETURN(r, s)				\
	if (ra == GETDNS_RETURN_ ## r) return(s);
#include "tbl/getdns_return.h"
	return ("INVALID");
}

struct VPFX(dynamic_resolver_context) *
dyn_getdns_get_context(struct VPFX(dynamic_resolver) *r)
{
	struct VPFX(dynamic_resolver_context) *c;

	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);

	AZ(pthread_mutex_lock(&r->mtx));
	c = VSLIST_FIRST(&r->contexts);
	while (c == NULL) {
		AZ(pthread_cond_wait(&r->cond, &r->mtx));
		c = VSLIST_FIRST(&r->contexts);
	}
	VSLIST_REMOVE_HEAD(&r->contexts, list);
	AZ(pthread_mutex_unlock(&r->mtx));

	CHECK_OBJ_NOTNULL(c, DYNAMIC_RESOLVER_CONTEXT_MAGIC);
	assert(c->resolver == r);

	return (c);
}

void
dyn_getdns_rel_context(struct VPFX(dynamic_resolver_context) **cp)
{
	struct VPFX(dynamic_resolver_context) *c;
	struct VPFX(dynamic_resolver) *r;
	int signal;

	TAKE_OBJ_NOTNULL(c, cp, DYNAMIC_RESOLVER_CONTEXT_MAGIC);
	r = c->resolver;
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);

	AZ(pthread_mutex_lock(&r->mtx));
	signal = (VSLIST_FIRST(&r->contexts) == NULL);
	VSLIST_INSERT_HEAD(&r->contexts, c, list);
	if (signal)
		AZ(pthread_cond_signal(&r->cond));
	AZ(pthread_mutex_unlock(&r->mtx));
}
