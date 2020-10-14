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
#include <vcl.h>

#include <string.h>	// miniobj.h

#include "vcc_dynamic_if.h"
#include "compat.h"

#include "dyn_getdns.h"
#include "dyn_resolver.h"

/* ------------------------------------------------------------
 * enum parsers
 */

static getdns_namespace_t
parse_res_namespace_e(VCL_ENUM e)
{
#define VMODENUM(n) if (e == VENUM(n)) return(GETDNS_NAMESPACE_ ## n);
#include "tbl/enum/res_namespace.h"
       WRONG("illegal enum");
}

static getdns_redirects_t
parse_res_redirects_e(VCL_ENUM e)
{
#define VMODENUM(n) if (e == VENUM(n)) return(GETDNS_ ## n);
#include "tbl/enum/res_redirects.h"
       WRONG("illegal enum");
}

static getdns_resolution_t
parse_res_resolution_type_e(VCL_ENUM e)
{
#define VMODENUM(n) if (e == VENUM(n)) return(GETDNS_RESOLUTION_ ## n);
#include "tbl/enum/res_resolution_type.h"
       WRONG("illegal enum");
}

static getdns_transport_list_t
parse_res_transport_e(VCL_ENUM e)
{
#define VMODENUM(n) if (e == VENUM(n)) return(GETDNS_TRANSPORT_ ## n);
#include "tbl/enum/res_transport.h"
       WRONG("illegal enum");
}

/* ------------------------------------------------------------
 * change tasks
 */

/* ------------------------------------------------------------
 * vmod interface
 */
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

const char * const funcpfx = "vmod_resolver_";

#define met_name(var)				\
	const char * var = __func__;		\
	assert(strlen(var) > strlen(funcpfx));	\
	var += strlen(funcpfx)

#define check_met_init(ctx)						\
	if (((ctx)->method & VCL_MET_INIT) == 0) {			\
		met_name(name);						\
		VRT_fail((ctx), "xresolver.%s"				\
		    " may only be called from vcl_init{}",		\
		    name);						\
		return (0);						\
	}

#define check_err(ctx, ret)						\
	if ((ret) != 0) {						\
		met_name(name);						\
		VRT_fail((ctx), "xresolver.%s"				\
		    " failed with error %d (%s)",			\
		    name, (ret), dyn_getdns_strerror(ret));		\
		return (0);						\
	}

#define context_apply(ctx, res, func, ...)				\
	do {								\
		getdns_return_t ret;					\
		struct VPFX(dynamic_resolver_context) *rctx;		\
		VSLIST_FOREACH(rctx, &(res)->contexts, list) {		\
			CHECK_OBJ_NOTNULL(rctx, DYNAMIC_RESOLVER_CONTEXT_MAGIC); \
			assert(rctx->resolver == (res));		\
			ret = func(rctx->context, __VA_ARGS__);		\
			check_err((ctx), ret);				\
		}							\
	} while(0)

VCL_BOOL
vmod_resolver_set_resolution_type(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM type_s)
{
	getdns_resolution_t type;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	type= parse_res_resolution_type_e(type_s);

	context_apply(ctx, r,
	    getdns_context_set_resolution_type, type);

	return (1);
}

struct res_cfg {
	unsigned		magic;
#define RES_CFG_MAGIC		0x04e50cf6
	size_t			namespace_count;
	getdns_namespace_t	namespaces[_GETDNS_NAMESPACE_COUNT];
	size_t			transport_count;
	getdns_transport_list_t transports[_GETDNS_TRANSPORT_COUNT];
};

static struct res_cfg *
res_cfg(VRT_CTX, const struct VPFX(dynamic_resolver) *r)
{
	struct vmod_priv *task;
	struct res_cfg *cfg;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	check_met_init(ctx);

	task = VRT_priv_task(ctx, r);

	if (task == NULL) {
		VRT_fail(ctx, "res_cfg: no priv_task");
		return (NULL);
	}

	if (task->priv) {
		CAST_OBJ_NOTNULL(cfg, task->priv, RES_CFG_MAGIC);
		return (cfg);
	}

	cfg = WS_Alloc(ctx->ws, sizeof *cfg);
	if (cfg == NULL) {
		VRT_fail(ctx, "res_cfg: WS_Alloc failed");
		return (NULL);
	}
	task->priv = cfg;
	INIT_OBJ(cfg, RES_CFG_MAGIC);
	return (cfg);
}

VCL_BOOL
vmod_resolver_clear_namespaces(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	struct res_cfg *cfg;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	cfg = res_cfg(ctx, r);
	if (cfg == NULL)
		return (0);

	cfg->namespace_count = 0;

	return (1);
}

VCL_BOOL
vmod_resolver_add_namespace(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM namespace_s)
{
	struct res_cfg *cfg;
	getdns_namespace_t namespace;
	size_t i;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	namespace = parse_res_namespace_e(namespace_s);

	cfg = res_cfg(ctx, r);
	if (cfg == NULL)
		return (0);

	for (i = 0; i < cfg->namespace_count; i++) {
		if (cfg->namespaces[i] == namespace) {
			VRT_fail(ctx, "tried to add namespace %s twice",
			    namespace_s);
			return (0);
		}
	}

	cfg->namespaces[cfg->namespace_count++] = namespace;

	return (1);
}

VCL_BOOL
vmod_resolver_set_namespaces(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	struct res_cfg *cfg;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	cfg = res_cfg(ctx, r);
	if (cfg == NULL)
		return (0);

	context_apply(ctx, r,
	    getdns_context_set_namespaces,
	    cfg->namespace_count, cfg->namespaces);

	return (1);
}

VCL_BOOL
vmod_resolver_clear_transports(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	struct res_cfg *cfg;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	cfg = res_cfg(ctx, r);
	if (cfg == NULL)
		return (0);

	cfg->transport_count = 0;

	return (1);
}

VCL_BOOL
vmod_resolver_add_transport(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM transport_s)
{
	struct res_cfg *cfg;

	getdns_transport_list_t transport;
	size_t i;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	transport = parse_res_transport_e(transport_s);

	cfg = res_cfg(ctx, r);
	if (cfg == NULL)
		return (0);

	for (i = 0; i < cfg->transport_count; i++) {
		if (cfg->transports[i] == transport) {
			VRT_fail(ctx, "tried to add transport %s twice",
			    transport_s);
			return (0);
		}
	}

	cfg->transports[cfg->transport_count++] = transport;

	return (1);
}

VCL_BOOL
vmod_resolver_set_transports(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	struct res_cfg *cfg;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	cfg = res_cfg(ctx, r);
	if (cfg == NULL)
		return (0);

	context_apply(ctx, r,
	    getdns_context_set_dns_transport_list,
	    cfg->transport_count, cfg->transports);

	return (1);
}

VCL_BOOL
vmod_resolver_set_idle_timeout(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_DURATION d)
{
	uint64_t idle_timeout = d * 1e3;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	context_apply(ctx, r,
	    getdns_context_set_idle_timeout, idle_timeout);

	return (1);
}

VCL_BOOL
vmod_resolver_set_limit_outstanding_queries(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_INT l)
{
	uint16_t limit;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	if (l < 0 || l > UINT16_MAX)
		check_err(ctx, GETDNS_RETURN_INVALID_PARAMETER);

	limit = (uint16_t)l;

	context_apply(ctx, r,
	    getdns_context_set_limit_outstanding_queries, limit);

	return (1);
}

VCL_BOOL
vmod_resolver_set_timeout(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_DURATION d)
{
	uint64_t timeout = d * 1e3;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	context_apply(ctx, r,
	    getdns_context_set_timeout, timeout);

	return (1);
}

VCL_BOOL
vmod_resolver_set_follow_redirects(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM redirect_s)
{
	getdns_redirects_t redirect;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r, DYNAMIC_RESOLVER_MAGIC);
	check_met_init(ctx);

	redirect = parse_res_redirects_e(redirect_s);

	context_apply(ctx, r,
	    getdns_context_set_follow_redirects,
	    redirect);

	return (1);
}
