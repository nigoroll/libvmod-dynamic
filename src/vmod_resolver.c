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
#include "dyn_resolver.h"

struct VPFX(dynamic_resolver) *
dyn_resolver_blob(VCL_BLOB blob)
{
	struct VPFX(dynamic_resolver) *p;

	if (blob && blob->type == DYNAMIC_RESOLVER_BLOB &&
	    blob->blob != NULL &&
	    blob->len == sizeof(struct VPFX(dynamic_resolver))) {
		CAST_OBJ_NOTNULL(p, TRUST_ME(blob->blob),
		    DYNAMIC_RESOLVER_MAGIC);
		return (p);
	}
	return (NULL);
}

// XXX mem-mgmt callbacks for addrinfo on workspace?!
VCL_VOID
vmod_resolver__init(VRT_CTX,
    struct VPFX(dynamic_resolver) **rp, const char *vcl_name,
    VCL_BOOL set_from_os, VCL_INT parallel)
{
	int i;
	getdns_return_t err;
	struct VPFX(dynamic_resolver) *r;
	struct VPFX(dynamic_resolver_context) *rctx;

	AN(rp);
	AZ(*rp);

	if (parallel < 1) {
		VRT_fail(ctx, "dynamic.resolver parallel must be 1 or higher");
		return;
	}

	ALLOC_OBJ(r, DYNAMIC_RESOLVER_MAGIC);
	if (r == NULL) {
		VRT_fail(ctx, "dynamic.resolver obj alloc failed");
		return;
	}

	REPLACE(r->vcl_name, vcl_name);
	if (r->vcl_name == NULL) {
		VRT_fail(ctx, "dynamic.resolver dup vcl_name failed");
		goto err_dup;
	}

	rctx = malloc(sizeof(*rctx) * parallel);
	if (rctx == NULL) {
		VRT_fail(ctx, "dynamic.resolver alloc rctx failed");
		goto err_rctx;
	}

	VSLIST_INIT(&r->contexts);
	for (i = 0; i < parallel; i++) {
		INIT_OBJ(&rctx[i], DYNAMIC_RESOLVER_CONTEXT_MAGIC);
		err = getdns_context_create(&rctx[i].context, set_from_os);
		if (err != GETDNS_RETURN_GOOD) {
			VRT_fail(ctx, "dynamic.resolver context init failed "
			    "error %d (%s)", err, dyn_getdns_strerror(err));
			break;
		}
		VSLIST_INSERT_HEAD(&r->contexts, &rctx[i], list);
		rctx[i].resolver = r;
	}

	if (i < parallel)
		goto err_getdns_create;

	AZ(pthread_mutex_init(&r->mtx, NULL));
	AZ(pthread_cond_init(&r->cond, NULL));

	VSLIST_FOREACH(rctx, &r->contexts, list)
		CHECK_OBJ_NOTNULL(rctx, DYNAMIC_RESOLVER_CONTEXT_MAGIC);

	r->n_contexts = parallel;
	r->freeptr = rctx;

	*rp = r;
	return;

  err_getdns_create:
	while (i < parallel && --i >= 0)
		getdns_context_destroy(rctx[i].context);
	free(rctx);
  err_rctx:
	free(r->vcl_name);
  err_dup:
	FREE_OBJ(r);
}

VCL_VOID
vmod_resolver__fini(struct VPFX(dynamic_resolver) **rp)
{
	int i = 0;
	struct VPFX(dynamic_resolver) *r;
	struct VPFX(dynamic_resolver_context) *rctx;

	r = *rp;
	*rp = NULL;

	if (r == NULL)
		return;

	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);

	AZ(pthread_cond_destroy(&r->cond));
	AZ(pthread_mutex_destroy(&r->mtx));

	VSLIST_FOREACH(rctx, &r->contexts, list) {
		i++;
		CHECK_OBJ_NOTNULL(rctx, DYNAMIC_RESOLVER_CONTEXT_MAGIC);
		assert(rctx->resolver == r);
		getdns_context_destroy(rctx->context);
	}

	assert(i == r->n_contexts);
	free(r->freeptr);
	free(r->vcl_name);
	FREE_OBJ(r);
}

VCL_BLOB
vmod_resolver_use(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);

	return (VRT_blob(ctx, "xresolver.use()", r, sizeof *r,
	    DYNAMIC_RESOLVER_BLOB));
}

VCL_BOOL
vmod_resolver_set_resolution_type(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM type_e)
{
	(void) r;
	(void) type_e;
	return (0);
}

VCL_BOOL
vmod_resolver_clear_namespaces(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	(void) r;
	return (0);
}

VCL_BOOL
vmod_resolver_add_namespace(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM namespace_e)
{
	(void) r;
	(void) namespace_e;
	return (0);
}

VCL_BOOL
vmod_resolver_set_namespaces(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	(void) r;
	return (0);
}

VCL_BOOL
vmod_resolver_clear_transports(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	(void) r;
	return (0);
}

VCL_BOOL
vmod_resolver_add_transport(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM transport_e)
{
	(void) r;
	(void) transport_e;
	return (0);
}

VCL_BOOL
vmod_resolver_set_transports(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	(void) r;
	return (0);
}

VCL_BOOL
vmod_resolver_set_idle_timeout(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_DURATION d)
{
	(void) r;
	(void) d;
	return (0);
}

VCL_BOOL
vmod_resolver_set_limit_outstanding_queries(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_INT limit)
{
	(void) r;
	(void) limit;
	return (0);
}

VCL_BOOL
vmod_resolver_set_timeout(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_DURATION d)
{
	(void) r;
	(void) d;
	return (0);
}

VCL_BOOL
vmod_resolver_set_follow_redirects(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM redirects_e)
{
	(void) r;
	(void) redirects_e;
	return (0);
}
