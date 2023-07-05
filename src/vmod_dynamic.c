/*-
 * Copyright (c) 2015-2016 Varnish Software AS
 * Copyright 2017-2023 UPLEX - Nils Goroll Systemoptimierung
 * All rights reserved.
 *
 * Authors: Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
 *	    Nils Goroll <nils.goroll@uplex.de>
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

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cache/cache.h>
#include <cache/cache_backend.h>

#include <vsa.h>
#include <vsb.h>
#include <vtim.h>
#include <vtcp.h>

#include "vcc_dynamic_if.h"
#include "dyn_resolver.h"
#include "vmod_dynamic.h"

static void
dylog(VRT_CTX, enum VSL_tag_e slt, const char *fmt, ...) v_printflike_(3, 4);
static void
dylog(VRT_CTX, enum VSL_tag_e slt, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ctx != NULL && ctx->vsl != NULL)
		VSLbv(ctx->vsl, slt, fmt, ap);
	else
		VSLv(slt, NO_VXID, fmt, ap);
	va_end(ap);
}

#define LOG(ctx, slt, dom, fmt, ...)					\
	do {								\
		dylog(ctx, slt,					\
		    "vmod-dynamic: %s %s %s:%s " fmt,			\
		    (dom)->obj->vcl_conf,				\
		    (dom)->obj->vcl_name, (dom)->addr,			\
		    dom_port(dom), __VA_ARGS__);			\
	} while (0)

#define DBG(ctx, dom, fmt, ...)						\
	do {								\
		if ((dom)->obj->debug)					\
			LOG(ctx, SLT_Debug, dom, fmt, __VA_ARGS__);	\
	} while (0)

#define dom_port(dom) (dom->port ? dom->port : dom->obj->port)

/*--------------------------------------------------------------------
 * Global data structures
 *
 * No locking required, mutated only by the CLI thread with guarantees that
 * they can't be accessed at the same time.
 */

static struct vmod_dynamic_head objects = VTAILQ_HEAD_INITIALIZER(objects);

struct VSC_lck *lck_be;
static struct VSC_lck *lck_dir;

static unsigned loadcnt = 0;

static const struct gethdr_s HDR_REQ_HOST = { HDR_REQ, "\005Host:"};
static const struct gethdr_s HDR_BEREQ_HOST = { HDR_BEREQ, "\005Host:"};

static struct vsc_seg * vsc = NULL;

// XXX table?
static const char * const share_s[SHARE_E_MAX] = {
	[DEFAULT]	= "DEFAULT",
	[DIRECTOR]	= "DIRECTOR",
	[HOST]		= "HOST"
};

static const char * const ttl_s[TTL_E_MAX] = {
	[cfg]	= "cfg",
	[dns]	= "dns",
	[min]	= "min",
	[max]	= "max",
};


/*--------------------------------------------------------------------
 * Director implementation
 */

void
dynamic_wait_active(struct dynamic_domain *dom)
{
	int ret;

	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);

	if (dom->status >= DYNAMIC_ST_ACTIVE)
		return;

	ret = Lck_CondWaitTimeout(&dom->resolve, &dom->mtx,
	    dom->obj->first_lookup_tmo);
	assert(ret == 0 || ret == ETIMEDOUT);
}

static VCL_BACKEND v_matchproto_(vdi_resolve_f)
dynamic_resolve(VRT_CTX, VCL_BACKEND d)
{
	struct dynamic_domain *dom;
	struct dynamic_ref *next;
	VCL_BACKEND dir;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, d->priv, DYNAMIC_DOMAIN_MAGIC);

	Lck_Lock(&dom->mtx);

	dynamic_wait_active(dom);

	if (dom->status > DYNAMIC_ST_ACTIVE) {
		Lck_Unlock(&dom->mtx);
		return (NULL);
	}

	if (dom->current == NULL)
		dom->current = VTAILQ_FIRST(&dom->refs);
	next = dom->current;

	do {
		CHECK_OBJ_ORNULL(next, DYNAMIC_REF_MAGIC);
		if (next != NULL)
			next = VTAILQ_NEXT(next, list);
		if (next == NULL)
			next = VTAILQ_FIRST(&dom->refs);
	} while (next != dom->current &&
		 !VRT_Healthy(ctx, next->dir, NULL));

	dom->current = next;

	Lck_Unlock(&dom->mtx);

	if (next == NULL)
		return (NULL);

	CHECK_OBJ(next, DYNAMIC_REF_MAGIC);

	dir = next->dir;

	return (dir);
}

static VCL_BOOL v_matchproto_(vdi_healthy_f)
dynamic_healthy(VRT_CTX, VCL_BACKEND d, VCL_TIME *changed)
{
	struct dynamic_domain *dom;
	struct dynamic_ref *r;
	unsigned retval = 0;
	double c, cc = 0;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, d->priv, DYNAMIC_DOMAIN_MAGIC);

	if (ctx->method != 0)
		Lck_Lock(&dom->mtx);
	else if (Lck_Trylock(&dom->mtx)) {
		/* avoid deadlock when in cli context */
		if (changed != NULL)
			*changed = dom->changed_cached;
		return (dom->healthy_cached);
	}

	dynamic_wait_active(dom);

	/* One healthy backend is enough for the director to be healthy */
	VTAILQ_FOREACH(r, &dom->refs, list) {
		CHECK_OBJ_NOTNULL(r->dir, DIRECTOR_MAGIC);
		retval = VRT_Healthy(ctx, r->dir, &c);
		if (c > cc)
			cc = c;
		if (retval)
			break;
	}

	Lck_Unlock(&dom->mtx);

	if (changed != NULL)
		*changed = cc;

	dom->changed_cached = cc;
	dom->healthy_cached = retval;
	return (retval);
}

static void v_matchproto_(vdi_list_f)
dynamic_list(VRT_CTX, VCL_BACKEND dir, struct vsb *vsb, int pflag, int jflag)
{
	const struct vmod_dynamic_director *obj;
	struct dynamic_domain *dom;
	struct dynamic_ref *r;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, dir->priv, DYNAMIC_DOMAIN_MAGIC);
	obj = dom->obj;
	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	VCL_BACKEND be;
	VCL_BOOL h;
	unsigned i = 0, nh = 0;

	if (pflag) {
		if (jflag) {
			VSB_cat(vsb, "{\n");
			VSB_indent(vsb, 2);
#define DIRPROP(n, fmt, code)						\
			VSB_printf(vsb, "\"%s\": " fmt ",\n", n, code);
#include "tbl/list_prop.h"
			VSB_cat(vsb, "\"backends\": {\n");
			VSB_indent(vsb, 2);
		} else {
			VSB_cat(vsb, "\n\n\tBackend\tHealth\n");
		}
	}

	Lck_Lock(&dom->mtx);
	VTAILQ_FOREACH(r, &dom->refs, list) {
		CHECK_OBJ(r, DYNAMIC_REF_MAGIC);
		be = r->dir;
		h = VRT_Healthy(ctx, be, NULL);
		if (h)
			nh++;
		if (pflag && jflag) {
			if (i)
				VSB_cat(vsb, ",\n");
			VSB_printf(vsb, "\"%s\": {\n",
			    be->vcl_name);
			VSB_indent(vsb, 2);
			VSB_printf(vsb, "\"health\": \"%s\"\n",
			    h ? "healthy" : "sick");
			VSB_indent(vsb, -2);
			VSB_cat(vsb, "}");
		}
		else if (pflag) {
			VSB_printf(vsb, "\t%s\t%s\n",
			    be->vcl_name,
			    h ? "healthy" : "sick");
		}
		i++;
	}
	Lck_Unlock(&dom->mtx);

	if (jflag && (pflag)) {
		VSB_cat(vsb, "\n");
		VSB_indent(vsb, -2);
		VSB_cat(vsb, "}\n");
		VSB_indent(vsb, -2);
		VSB_cat(vsb, "},\n");
	}

	if (pflag)
		return;

	if (jflag)
		VSB_printf(vsb, "[%u, %u, \"%s\"]", nh, i,
		    nh ? "healthy" : "sick");
	else
		VSB_printf(vsb, "%u/%u\t%s", nh, i, nh ? "healthy" : "sick");
}

/*--------------------------------------------------------------------
 * Background job
 */

static void
ref_del(VRT_CTX, struct dynamic_ref *r)
{
	struct backend *be;

	AN(r);
	CHECK_OBJ_ORNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r->dom, DYNAMIC_DOMAIN_MAGIC);

	CHECK_OBJ_NOTNULL(r->dir, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(be, r->dir->priv, BACKEND_MAGIC);

	DBG(ctx, r->dom, "unref-backend %s", be->vcl_name);
	VRT_Assign_Backend(&r->dir, NULL);
	if (r->sa != NULL)
		VSA_free(&r->sa);
	FREE_OBJ(r);
}

static struct dynamic_ref *
ref_new(struct dynamic_domain *dom)
{
	struct dynamic_ref *r;

	ALLOC_OBJ(r, DYNAMIC_REF_MAGIC);
	AN(r);
	r->dom = dom;
	r->keep = dom->obj->keep;
	return (r);
}

/* clone an existing reference under a different domain */
static struct dynamic_ref *
ref_clone(VRT_CTX, struct dynamic_domain *dom, const struct dynamic_ref *s)
{
	struct dynamic_ref *r;
	struct backend *be;

	CHECK_OBJ_NOTNULL(s, DYNAMIC_REF_MAGIC);
	CHECK_OBJ_NOTNULL(s->dir, DIRECTOR_MAGIC);

	assert(dom != s->dom);

	r = ref_new(dom);
	VRT_Assign_Backend(&r->dir, s->dir);
	r->keep = dom->obj->keep;
	if (s->sa)
		r->sa = VSA_Clone(s->sa);

	VTAILQ_INSERT_TAIL(&dom->refs, r, list);

	CAST_OBJ_NOTNULL(be, s->dir->priv, BACKEND_MAGIC);

	DBG(ctx, dom, "ref-backend %s", be->vcl_name);

	return (r);
}

/* select endpoint address matching sa proto */
static const struct suckaddr *
vep_select(const struct vrt_endpoint *vep, const struct suckaddr *sa)
{

	CHECK_OBJ_NOTNULL(vep, VRT_ENDPOINT_MAGIC);
	switch (VSA_Get_Proto(sa)) {
	case AF_INET:
		return(vep->ipv4);
	case AF_INET6:
		return(vep->ipv6);
	default:
		WRONG("unexpected family");
	}
}

static int
vep_compare(const struct vrt_endpoint *vep, const struct suckaddr *sa)
{
	const struct suckaddr *vepsa;

	vepsa = vep_select(vep, sa);
	if (vepsa == NULL)
		return (-1);
	return (VSA_Compare(vepsa, sa));
}

static int
bedir_compare_ip(VCL_BACKEND d, const struct suckaddr *sa)
{
	struct backend *be;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(be, d->priv, BACKEND_MAGIC);
	return (vep_compare(be->endpoint, sa));
}

static inline int
ref_compare_ip(struct dynamic_ref *r, const struct suckaddr *sa)
{

	CHECK_OBJ_NOTNULL(r, DYNAMIC_REF_MAGIC);
	return (r->sa ? VSA_Compare(r->sa, sa) : bedir_compare_ip(r->dir, sa));
}

static int
dynamic_whitelisted(VRT_CTX, const struct dynamic_domain *dom,
    const struct suckaddr *sa)
{
	const struct vmod_dynamic_director *obj;
	char addr[VTCP_ADDRBUFSIZE];
	char port[VTCP_PORTBUFSIZE];

	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
	obj = dom->obj;
	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	if (obj->whitelist == NULL)
		return (1);

	if (VRT_acl_match(ctx, obj->whitelist, sa))
		return (1);

	VTCP_name(sa, addr, sizeof addr, port, sizeof port);
	LOG(ctx, SLT_Error, dom, "whitelist mismatch %s:%s", addr, port);

	return (0);
}

/* all parameters owned by caller */
static void
dynamic_add(VRT_CTX, struct dynamic_domain *dom, const struct res_info *info)
{
	char addr[VTCP_ADDRBUFSIZE];
	char port[VTCP_PORTBUFSIZE];
	char vcl_name[1024];
	struct vrt_backend vrt;
	struct vrt_endpoint ep;
	struct dynamic_ref *r;

	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
	CHECK_OBJ_NOTNULL(dom->obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	AN(info);
	Lck_AssertHeld(&dom->mtx);
	Lck_AssertHeld(&dom->obj->mtx);

	VTCP_name(info->sa, addr, sizeof addr, port, sizeof port);

	INIT_OBJ(&vrt, VRT_BACKEND_MAGIC);

	switch (dom->obj->share) {
	case DIRECTOR:
		vrt.authority = vrt.hosthdr = dom->obj->hosthdr;
		bprintf(vcl_name, "%s(%s:%s)", dom->obj->vcl_name, addr,
		    dom_port(dom));
		break;
	case HOST:
		vrt.authority = vrt.hosthdr =
		    (dom->obj->hosthdr ? dom->obj->hosthdr : dom->addr);
		bprintf(vcl_name, "%s.%s(%s:%s)", dom->obj->vcl_name, dom->addr,
		    addr, dom_port(dom));
		break;
	default:
		INCOMPL();
	}

	vrt.vcl_name = vcl_name;
	vrt.probe = dom->obj->probe;
	vrt.connect_timeout = dom->obj->connect_tmo;
	vrt.first_byte_timeout = dom->obj->first_byte_tmo;
	vrt.between_bytes_timeout = dom->obj->between_bytes_tmo;
	vrt.max_connections = dom->obj->max_connections;
	vrt.proxy_header = dom->obj->proxy_header;
	assert(vrt.proxy_header <= 2);
	INIT_OBJ(&ep, VRT_ENDPOINT_MAGIC);

	switch (VSA_Get_Proto(info->sa)) {
	case AF_INET:
		ep.ipv4 = info->sa;
		break;
	case AF_INET6:
		ep.ipv6 = info->sa;
		break;
	default:
		WRONG("unexpected family");
	}
	vrt.endpoint = &ep;

	/* VRT_new_backend comes with a reference */
	r = ref_new(dom);
	r->dir = VRT_new_backend(ctx, &vrt, dom->obj->via);
	if (dom->obj->via != NULL)
		r->sa = VSA_Clone(info->sa);
	VTAILQ_INSERT_TAIL(&dom->refs, r, list);

	DBG(ctx, dom, "new-backend %s", vrt.vcl_name);

	return;
}

static void
dynamic_update_domain(struct dynamic_domain *dom, const struct res_cb *res,
    void *priv, vtim_real now)
{
	struct dynamic_domain *dom2;
	struct dynamic_ref *r, *r2;
	struct vrt_ctx ctx;
	uint8_t suckbuf[vsa_suckaddr_len];
	struct res_info ibuf[1] = {{ .suckbuf = suckbuf }};
	struct res_info *info;
	void *state = NULL;
	vtim_dur ttl = NAN;

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = dom->obj->vcl;

	Lck_Lock(&dom->obj->mtx);
	Lck_Lock(&dom->mtx);

	// refs first in oldrefs
	VTAILQ_SWAP(&dom->refs, &dom->oldrefs, dynamic_ref, list);
	VTAILQ_CONCAT(&dom->oldrefs, &dom->refs, list);
	assert(VTAILQ_EMPTY(&dom->refs));

	while ((info = res->result(ibuf, priv, &state)) != NULL) {
		if (! dynamic_whitelisted(&ctx, dom, info->sa))
			continue;

		if (info->ttl != 0 && (isnan(ttl) || info->ttl < ttl))
			ttl = info->ttl;

		/* search this domain's backends */
		VTAILQ_FOREACH(r, &dom->oldrefs, list) {
			if (! ref_compare_ip(r, info->sa))
				break;
		}
		if (r != NULL) {
			VTAILQ_REMOVE(&dom->oldrefs, r, list);
			VTAILQ_INSERT_TAIL(&dom->refs, r, list);
			r->keep = dom->obj->keep;
			continue;
		}

		if (dom->obj->share == HOST)
			goto add_dom;

		/* search the director's other domains */
		AZ(r);
		VTAILQ_FOREACH(dom2, &dom->obj->active_domains, list) {
			if (dom2 == dom)
				continue;
			CHECK_OBJ_NOTNULL(dom2, DYNAMIC_DOMAIN_MAGIC);
			Lck_Lock(&dom2->mtx);
			VTAILQ_FOREACH(r, &dom2->refs, list) {
				if (! ref_compare_ip(r, info->sa))
					break;
			}
			if (r != NULL)
				r = ref_clone(&ctx, dom, r);
			Lck_Unlock(&dom2->mtx);
			if (r != NULL)
				break;
		}
		if (r != NULL)
			continue;

	  add_dom:
		dynamic_add(&ctx, dom, info);
	}

	Lck_Unlock(&dom->obj->mtx);

	VTAILQ_FOREACH_SAFE(r, &dom->oldrefs, list, r2) {
		CHECK_OBJ_NOTNULL(r, DYNAMIC_REF_MAGIC);
		if (r == dom->current)
			dom->current = VTAILQ_FIRST(&dom->refs);
	}

	Lck_Unlock(&dom->mtx);

	VTAILQ_FOREACH_SAFE(r, &dom->oldrefs, list, r2) {
		CHECK_OBJ(r, DYNAMIC_REF_MAGIC);
		if (r->keep--)
			continue;
		VTAILQ_REMOVE(&dom->oldrefs, r, list);
		ref_del(&ctx, r);
	}

	// deadline only used by this thread - safe outside lock
	if (isnan(ttl)) {
		ttl = dom->obj->ttl;
	} else if (dom->obj->ttl_from == cfg) {
		ttl = dom->obj->ttl;
	} else if (dom->obj->ttl_from == min) {
		if (dom->obj->ttl < ttl)
			ttl = dom->obj->ttl;
	} else if (dom->obj->ttl_from == max) {
		if (dom->obj->ttl > ttl)
			ttl = dom->obj->ttl;
	} else {
		assert(dom->obj->ttl_from == dns);
	}
	dom->deadline = now + ttl;
}

static void
dynamic_timestamp(struct dynamic_domain *dom, const char *event, double start,
    double dfirst, double dprev)
{

	VSL(SLT_Timestamp, NO_VXID, "vmod-dynamic %s.%s(%s:%s) %s: %.6f %.6f %.6f",
	    dom->obj->vcl_conf, dom->obj->vcl_name, dom->addr, dom_port(dom),
	    event, start, dfirst, dprev);
}

static void*
dynamic_lookup_thread(void *priv)
{
	struct vmod_dynamic_director *obj;
	struct dynamic_domain *dom;
	struct vrt_ctx ctx;
	vtim_real lookup, results, update;
	const struct res_cb *res;
	void *res_priv = NULL;
	int ret;

	CAST_OBJ_NOTNULL(dom, priv, DYNAMIC_DOMAIN_MAGIC);
	INIT_OBJ(&ctx, VRT_CTX_MAGIC);

	obj = dom->obj;
	res = obj->resolver;

	assert(dom->status == DYNAMIC_ST_STARTING);

	while (obj->active && dom->status <= DYNAMIC_ST_ACTIVE) {

		lookup = VTIM_real();
		if (lookup > dom->expires) {
			LOG(NULL, SLT_VCL_Log, dom, "%s", "timeout");
			dom->status = DYNAMIC_ST_STALE;
			break;
		}

		dynamic_timestamp(dom, "Lookup", lookup, 0., 0.);

		ret = res->lookup(obj->resolver_inst, dom->addr,
		    dom_port(dom), &res_priv);

		results = VTIM_real();
		dynamic_timestamp(dom, "Results", results, results - lookup,
		    results - lookup);

		if (ret == 0) {
			dynamic_update_domain(dom, res, res_priv, results);
			update = VTIM_real();
			dynamic_timestamp(dom, "Update", update,
			    update - lookup, update - results);
		} else {
			LOG(&ctx, SLT_Error, dom, "%s %d (%s)",
			    res->name, ret, res->strerror(ret));
			dom->deadline = results + obj->retry_after;
			dbg_res_details(NULL, dom->obj, res, res_priv);
		}

		res->fini(&res_priv);
		AZ(res_priv);

		Lck_Lock(&dom->mtx);

		if (dom->status == DYNAMIC_ST_STARTING) {
			AZ(pthread_cond_broadcast(&dom->resolve));
			dom->status = DYNAMIC_ST_ACTIVE;
		}

		/* Check status again after the blocking call */
		if (obj->active && dom->status <= DYNAMIC_ST_ACTIVE) {
			ret = Lck_CondWaitUntil(&dom->cond, &dom->mtx,
			    fmin(dom->deadline, dom->expires));
			assert(ret == 0 || ret == ETIMEDOUT);
		}

		Lck_Unlock(&dom->mtx);
	}

	if (dom->status == DYNAMIC_ST_STALE) {
		Lck_Lock(&obj->mtx);
		VTAILQ_REMOVE(&obj->active_domains, dom, list);
		VTAILQ_INSERT_TAIL(&obj->purged_domains, dom, list);
		Lck_Unlock(&obj->mtx);
	}
	else
		dom->status = DYNAMIC_ST_DONE;

	dynamic_timestamp(dom, "Done", VTIM_real(), 0., 0.);

	return (NULL);
}

static void
dynamic_free(struct dynamic_domain *dom)
{

	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);

	AZ(dom->thread);
	LOG(NULL, SLT_VCL_Log, dom, "%s", "deleted");
	VRT_DelDirector(&dom->dir);
}

static enum dynamic_status_e
dynamic_join(struct dynamic_domain *dom)
{
	enum dynamic_status_e status;

	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
	AN(dom->thread);
	AZ(pthread_join(dom->thread, NULL));
	status = dom->status;
	assert(status == DYNAMIC_ST_DONE || status == DYNAMIC_ST_STALE);
	dom->thread = 0;
	dom->status = DYNAMIC_ST_READY;
	return (status);
}

static void
dynamic_gc_purged(struct vmod_dynamic_director *obj)
{
	struct dynamic_domain *dom;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);

	while ((dom = VTAILQ_FIRST(&obj->purged_domains)) != NULL) {
		CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
		assert(dom->status == DYNAMIC_ST_STALE);
		VTAILQ_REMOVE(&obj->purged_domains, dom, list);
		Lck_Unlock(&obj->mtx);
		(void) dynamic_join(dom);
		dynamic_free(dom);
		Lck_Lock(&obj->mtx);
	}
}

static void
dynamic_stop(struct vmod_dynamic_director *obj)
{
	struct dynamic_domain *dom;
	struct dynamic_domain_head active_done;
	enum dynamic_status_e status;

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	service_stop(obj);

	VTAILQ_INIT(&active_done);

	Lck_Lock(&obj->mtx);
	AZ(obj->active);
	// obj-active has been cleared, wake up all threads
	VTAILQ_FOREACH(dom, &obj->active_domains, list) {
		CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
		Lck_Lock(&dom->mtx);
		AN(dom->thread);
		AZ(pthread_cond_signal(&dom->cond));
		Lck_Unlock(&dom->mtx);
	}

	while (! (VTAILQ_EMPTY(&obj->purged_domains) &&
		  VTAILQ_EMPTY(&obj->active_domains))) {
		// finished threads can be picked up already
		dynamic_gc_purged(obj);

		while ((dom = VTAILQ_FIRST(&obj->active_domains)) != NULL) {
			CHECK_OBJ(dom, DYNAMIC_DOMAIN_MAGIC);
			Lck_Unlock(&obj->mtx);
			status = dynamic_join(dom);
			assert(dom->status == DYNAMIC_ST_READY);
			Lck_Lock(&obj->mtx);
			AZ(dom->thread);
			switch (status) {
			case DYNAMIC_ST_STALE:
				VTAILQ_REMOVE(&obj->purged_domains, dom, list);
				dynamic_free(dom);
				break;
			case DYNAMIC_ST_DONE:
				VTAILQ_REMOVE(&obj->active_domains, dom, list);
				VTAILQ_INSERT_TAIL(&active_done, dom, list);
				break;
			default:
				WRONG("status in dynamic_stop");
			}
		}
	}
	assert(VTAILQ_EMPTY(&obj->active_domains));
	VTAILQ_SWAP(&obj->active_domains, &active_done, dynamic_domain, list);
	Lck_Unlock(&obj->mtx);

	VRT_VCL_Allow_Discard(&obj->vclref);
}

static void
dynamic_start_domain(struct dynamic_domain *dom)
{
	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
	if (dom->status >= DYNAMIC_ST_STARTING)
		return;
	assert(dom->status == DYNAMIC_ST_READY);
	dom->status = DYNAMIC_ST_STARTING;
	AZ(dom->thread);
	AZ(pthread_create(&dom->thread, NULL, dynamic_lookup_thread, dom));
}

static void
dynamic_start(VRT_CTX, struct vmod_dynamic_director *obj)
{
	struct dynamic_domain *dom;
	char buf[128];

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	AZ(obj->vclref);

	bprintf(buf, "dynamic director %s", obj->vcl_name);
	/* name argument is being strdup()ed via REPLACE() */
	obj->vclref = VRT_VCL_Prevent_Discard(ctx, buf);

	Lck_Lock(&obj->mtx);
	VTAILQ_FOREACH(dom, &obj->active_domains, list)
	    dynamic_start_domain(dom);

	service_start(ctx, obj);
	Lck_Unlock(&obj->mtx);
}

static struct dynamic_domain *
dynamic_search(struct vmod_dynamic_director *obj, const char *addr,
    const char *port)
{
	struct dynamic_domain *dom;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);
	AN(addr);

	if (VTAILQ_FIRST(&obj->purged_domains))
		dynamic_gc_purged(obj);

	if (port != NULL)
		AN(*port);

	VTAILQ_FOREACH(dom, &obj->active_domains, list) {
		CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
		if (!strcmp(dom->addr, addr) &&
		    (port == NULL || !strcmp(dom_port(dom), port)))
			break;
	}

	return (dom);
}

static void v_matchproto_(vdi_release_f)
dynamic_release(VCL_BACKEND dir)
{
	struct dynamic_ref *r, *r2;
	struct dynamic_domain *dom;

	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, dir->priv, DYNAMIC_DOMAIN_MAGIC);

	AZ(dom->thread);
	assert(dom->status == DYNAMIC_ST_READY);

	VTAILQ_FOREACH_SAFE(r, &dom->refs, list, r2) {
		CHECK_OBJ(r, DYNAMIC_REF_MAGIC);
		VTAILQ_REMOVE(&dom->refs, r, list);
		ref_del(NULL, r);
	}
	VTAILQ_FOREACH_SAFE(r, &dom->oldrefs, list, r2) {
		CHECK_OBJ(r, DYNAMIC_REF_MAGIC);
		VTAILQ_REMOVE(&dom->oldrefs, r, list);
		ref_del(NULL, r);
	}
}

static void v_matchproto_(vdi_destroy_f)
dynamic_destroy(VCL_BACKEND dir)
{
	struct dynamic_domain *dom;

	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, dir->priv, DYNAMIC_DOMAIN_MAGIC);

	AZ(dom->thread);
	assert(dom->status == DYNAMIC_ST_READY);
	assert(VTAILQ_EMPTY(&dom->refs));
	assert(VTAILQ_EMPTY(&dom->oldrefs));

	AZ(pthread_cond_destroy(&dom->resolve));
	AZ(pthread_cond_destroy(&dom->cond));
	Lck_Delete(&dom->mtx);
	REPLACE(dom->addr, NULL);
	REPLACE(dom->port, NULL);
	FREE_OBJ(dom);
}

static const struct vdi_methods vmod_dynamic_methods[1] = {{
	.magic =	VDI_METHODS_MAGIC,
	.type =		"dynamic",
	.healthy =	dynamic_healthy,
	.resolve =	dynamic_resolve,
	.release =	dynamic_release,
	.destroy =	dynamic_destroy,
	.list =	dynamic_list
}};

struct dynamic_domain *
dynamic_get(VRT_CTX, struct vmod_dynamic_director *obj, const char *addr,
    const char *port)
{
	struct dynamic_domain *dom;
	VCL_TIME t;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);
	AN(addr);

	t = ctx->now + obj->domain_usage_tmo;

	dom = dynamic_search(obj, addr, port);
	if (dom != NULL) {
		if (t > dom->expires)
			dom->expires = t;
		return (dom);
	}

	ALLOC_OBJ(dom, DYNAMIC_DOMAIN_MAGIC);
	AN(dom);
	VTAILQ_INIT(&dom->refs);
	VTAILQ_INIT(&dom->oldrefs);
	REPLACE(dom->addr, addr);
	REPLACE(dom->port, port);

	dom->obj = obj;
	dom->expires = t;

	dom->dir = VRT_AddDirector(ctx, vmod_dynamic_methods, dom,
	    "%s(%s:%s)", obj->vcl_name, addr, port);

	Lck_New(&dom->mtx, lck_be);
	AZ(pthread_cond_init(&dom->cond, NULL));
	AZ(pthread_cond_init(&dom->resolve, NULL));

	obj->active = 1;
	dynamic_start_domain(dom);

	VTAILQ_INSERT_TAIL(&obj->active_domains, dom, list);

	return (dom);
}

/*--------------------------------------------------------------------
 * VMOD interfaces
 */

int v_matchproto_(vmod_event_f)
vmod_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	struct vmod_dynamic_director *obj;
	unsigned active;

	ASSERT_CLI();
	AN(ctx);
	AN(ctx->vcl);
	AN(priv);

	switch (e) {
	case VCL_EVENT_LOAD:
		if (loadcnt++ == 0) {
			AZ(vsc);
			lck_dir = Lck_CreateClass(&vsc, "dynamic.director");
			if (vsc == NULL) {
				VRT_fail(ctx, "Could not create Lock class");
				return (1);
			}
			lck_be = Lck_CreateClass(&vsc, "dynamic.backend");
		}
		AN(vsc);
		AN(lck_dir);
		AN(lck_be);
		return (0);
	case VCL_EVENT_DISCARD:
		assert(loadcnt > 0);
		AN(vsc);
		if (--loadcnt == 0) {
			Lck_DestroyClass(&vsc);
			AZ(vsc);
		}
		return (0);
	case VCL_EVENT_WARM:
		active = 1;
		break;
	case VCL_EVENT_COLD:
		active = 0;
		break;
	default:
		WRONG("Unhandled vmod event");
	}

	/* no locking: guaranteed to happen in the CLI thread */
	VTAILQ_FOREACH(obj, &objects, list) {
		if (obj->vcl != ctx->vcl)
			continue;

		obj->active = active;
		if (active)
			dynamic_start(ctx, obj);
		else
			dynamic_stop(obj);
	}
	return (0);
}

static inline enum dynamic_share_e
dynamic_share_parse(const char *s)
{
	switch (s[0]) {
	case 'D':
		switch (s[1]) {
		case 'E':
			return DEFAULT;
		case 'I':
			return DIRECTOR;
		default:
			INCOMPL();
		}
	case 'H':
		return HOST;
	default:
		INCOMPL();
	}
}

static inline enum dynamic_ttl_e
dynamic_ttl_parse(const char *s)
{
	switch (s[0]) {
	case 'c':	return cfg;
	case 'd':	return dns;
	default:	break;
	}
	assert(s[0] == 'm');
	switch (s[1]) {
	case 'i':	return min;
	case 'a':	return max;
	default:	break;
	}
	INCOMPL();
}


VCL_VOID v_matchproto_()
vmod_director__init(VRT_CTX,
    struct vmod_dynamic_director **objp,
    const char *vcl_name,
    VCL_STRING port,
    VCL_STRING hosthdr,
    VCL_ENUM share_arg,
    VCL_PROBE probe,
    VCL_ACL whitelist,
    VCL_DURATION ttl,
    VCL_DURATION connect_timeout,
    VCL_DURATION first_byte_timeout,
    VCL_DURATION between_bytes_timeout,
    VCL_DURATION domain_usage_timeout,
    VCL_DURATION first_lookup_timeout,
    VCL_INT max_connections,
    VCL_INT proxy_header,
    VCL_BLOB resolver,
    VCL_ENUM ttl_from_arg,
    VCL_DURATION retry_after,
    VCL_BACKEND via,
    VCL_INT keep)
{
	struct vmod_dynamic_director *obj;

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(objp);
	AZ(*objp);
	AN(vcl_name);
	CHECK_OBJ_ORNULL(probe, VRT_BACKEND_PROBE_MAGIC);

	if (port == NULL || *port == '\0') {
		VRT_fail(ctx, "dynamic.director(): port may not be empty");
                return;
        }
	if (ttl == 0) {
		VRT_fail(ctx, "dynamic.director(): ttl may not be 0s");
                return;
        }
	if (domain_usage_timeout == 0) {
		VRT_fail(ctx, "dynamic.director(): domain_usage_timeout may "
                    "not be 0s");
                return;
        }
	if (first_lookup_timeout == 0) {
		VRT_fail(ctx, "dynamic.director(): first_lookup_timeout may "
                    "not be 0s");
                return;
        }
	if (keep < 0) {
		VRT_fail(ctx, "dynamic.director(): keep may not be negative");
                return;
        }
	if (keep > UINT_MAX)
		keep = UINT_MAX;

        assert(ttl > 0);
        assert(domain_usage_timeout > 0);
        assert(first_lookup_timeout > 0);
	assert(connect_timeout >= 0);
	assert(first_byte_timeout >= 0);
	assert(between_bytes_timeout >= 0);
	assert(max_connections >= 0);
	assert(proxy_header >= 0);

	ALLOC_OBJ(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	AN(obj);
	VTAILQ_INIT(&obj->active_domains);
	VTAILQ_INIT(&obj->purged_domains);
	VTAILQ_INIT(&obj->active_services);
	VTAILQ_INIT(&obj->purged_services);
	REPLACE(obj->vcl_name, vcl_name);
	REPLACE(obj->port, port);

	obj->vcl_conf = VCL_Name(ctx->vcl);
	obj->vcl = ctx->vcl;
	obj->active = 0;
	obj->hosthdr = hosthdr;
	obj->share = dynamic_share_parse(share_arg);
	obj->probe = probe;
	obj->whitelist = whitelist;
	obj->ttl = ttl;
	obj->retry_after = retry_after;
	obj->connect_tmo = connect_timeout;
	obj->first_byte_tmo = first_byte_timeout;
	obj->between_bytes_tmo = between_bytes_timeout;
	if (domain_usage_timeout == 0)
		obj->domain_usage_tmo = HUGE_VAL;
	else
		obj->domain_usage_tmo = domain_usage_timeout;
	obj->first_lookup_tmo = first_lookup_timeout;
	obj->max_connections = (unsigned)max_connections;
	obj->proxy_header = (unsigned)proxy_header;
	obj->ttl_from = dynamic_ttl_parse(ttl_from_arg);
	obj->keep = (unsigned)keep;

	if (resolver != NULL) {
		obj->resolver = &res_getdns;
		obj->resolver_inst = dyn_resolver_blob(resolver);
		if (obj->resolver_inst == NULL)
			VRT_fail(ctx, "dynamic.director(): "
			    "invalid resolver argument");
	} else {
		if (obj->ttl_from != cfg)
			VRT_fail(ctx, "dynamic.director(): "
			    "ttl_from = %s only valid with resolver",
			    ttl_from_arg);
		obj->resolver = &res_gai;
	}

	obj->via = via;
	if (obj->share == DEFAULT)
		obj->share = via ? HOST : DIRECTOR;


	Lck_New(&obj->mtx, lck_dir);

	VTAILQ_INSERT_TAIL(&objects, obj, list);
	*objp = obj;
}

VCL_VOID v_matchproto_()
vmod_director__fini(struct vmod_dynamic_director **objp)
{
	struct vmod_dynamic_director *obj;
	struct dynamic_domain *dom, *d2;

	ASSERT_CLI();
	AN(objp);
	obj = *objp;
	*objp = NULL;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	AZ(obj->active);

	VTAILQ_REMOVE(&objects, obj, list);

	service_fini(obj);

	// removed by transition to cold / active == 0
	assert(VTAILQ_EMPTY(&obj->purged_domains));

	VTAILQ_FOREACH_SAFE(dom, &obj->active_domains, list, d2) {
		VTAILQ_REMOVE(&obj->active_domains, dom, list);
		dynamic_free(dom);
	}

	assert(VTAILQ_EMPTY(&obj->purged_domains));
	assert(VTAILQ_EMPTY(&obj->active_domains));
	Lck_Delete(&obj->mtx);
	free(obj->vcl_name);
	FREE_OBJ(obj);
}

VCL_BACKEND v_matchproto_(td_dynamic_director_backend)
vmod_director_backend(VRT_CTX, struct vmod_dynamic_director *obj,
    VCL_STRING host, VCL_STRING port)
{
	struct dynamic_domain *dom;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	if ((host == NULL || *host == '\0') && ctx->http_bereq != NULL)
		host = VRT_GetHdr(ctx, &HDR_BEREQ_HOST);

	if ((host == NULL || *host == '\0') && ctx->http_req != NULL)
		host = VRT_GetHdr(ctx, &HDR_REQ_HOST);

	if (host == NULL || *host == '\0')
		return (NULL);

	if (port != NULL && *port == '\0')
		port = NULL;
	Lck_Lock(&obj->mtx);
	dom = dynamic_get(ctx, obj, host, port);
	AN(dom);
	Lck_Unlock(&obj->mtx);

	return (dom->dir);
}

VCL_VOID v_matchproto_(td_dynamic_director_debug)
vmod_director_debug(VRT_CTX, struct vmod_dynamic_director *obj,
    VCL_BOOL enable)
{

	(void)ctx;
	obj->debug = enable;
}
