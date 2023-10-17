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

#include <vmb.h>
#include <vsa.h>
#include <vsb.h>
#include <vtim.h>
#include <vtcp.h>

#include "vcc_dynamic_if.h"
#include "dyn_resolver.h"
#include "vmod_dynamic.h"

void
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
		    "vmod-dynamic %s %s %s:%s " fmt,			\
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

static void dynamic_gc_expired(struct vmod_dynamic_director *obj);

/*--------------------------------------------------------------------
 * active domains tree
 */

static inline int
dynamic_domain_cmp(const struct dynamic_domain *a,
    const struct dynamic_domain *b)
{
	int r;

	CHECK_OBJ_NOTNULL(a, DYNAMIC_DOMAIN_MAGIC);
	CHECK_OBJ_NOTNULL(b, DYNAMIC_DOMAIN_MAGIC);

	r = strcmp(a->addr, b->addr);
	if (r)
		return (r);

	if (a->authority == NULL && b->authority == NULL)
		goto port_cmp;
	if (a->authority == NULL)
		return (1);
	if (b->authority == NULL)
		return (-1);

	r = strcmp(a->authority, b->authority);
	if (r)
		return (r);

  port_cmp:
	return (strcmp(dom_port(a), dom_port(b)));
}

#define VRBT_GENERATE_NEEDED(name, type, field, cmp, attr)	\
	VRBT_GENERATE_RANK(name, type, field, attr)		\
	VRBT_GENERATE_INSERT_COLOR(name, type, field, attr)	\
	VRBT_GENERATE_REMOVE_COLOR(name, type, field, attr)	\
	VRBT_GENERATE_INSERT_FINISH(name, type, field, attr)	\
	VRBT_GENERATE_INSERT(name, type, field, cmp, attr)	\
	VRBT_GENERATE_REMOVE(name, type, field, attr)		\
	VRBT_GENERATE_FIND(name, type, field, cmp, attr)	\
	VRBT_GENERATE_NEXT(name, type, field, attr)		\
	VRBT_GENERATE_MINMAX(name, type, field, attr)

/* unused

   VRBT_GENERATE_NFIND(name, type, field, cmp, attr)
   VRBT_GENERATE_REINSERT(name, type, field, cmp, attr)
   VRBT_GENERATE_INSERT_PREV(name, type, field, cmp, attr)
   VRBT_GENERATE_INSERT_NEXT(name, type, field, cmp, attr)
   VRBT_GENERATE_PREV(name, type, field, attr)
*/

VRBT_GENERATE_NEEDED(dom_tree_head, dynamic_domain,
    link.tree, dynamic_domain_cmp, static)

/*--------------------------------------------------------------------
 * Director implementation
 */

void
dom_wait_active(struct dynamic_domain *dom)
{
	int ret;

	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);

	if (dom->status >= DYNAMIC_ST_ACTIVE)
		return;

	DBG(NULL, dom, "%s", "wait-active");

	ret = 0;
	while (ret == 0 && dom->status < DYNAMIC_ST_ACTIVE)
		ret = Lck_CondWaitTimeout(&dom->resolve, &dom->mtx,
		    dom->obj->first_lookup_tmo);
	assert(ret == 0 || ret == ETIMEDOUT);
	DBG(NULL, dom, "wait-active ret %d", ret);
}

static VCL_BACKEND v_matchproto_(vdi_resolve_f)
dom_resolve(VRT_CTX, VCL_BACKEND d)
{
	struct dynamic_domain *dom;
	struct dynamic_ref *next, *alt;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, d->priv, DYNAMIC_DOMAIN_MAGIC);

	/*
	 * We need to gc somewhere where our code
	 * runs outside the update thread in order to be able to
	 * call pthread_join().
	 *
	 * other options: extra thread, pool_task (needs cache_varnishd.h)
	 */
	if (VTAILQ_FIRST(&dom->obj->unref_domains))
		dynamic_gc_expired(dom->obj);

	Lck_Lock(&dom->mtx);

	dom_wait_active(dom);

	if (dom->status > DYNAMIC_ST_ACTIVE) {
		Lck_Unlock(&dom->mtx);
		return (NULL);
	}

	if (dom->current == NULL)
		dom->current = VTAILQ_FIRST(&dom->refs);
	next = dom->current;
	alt = NULL;
	do {
		CHECK_OBJ_ORNULL(next, DYNAMIC_REF_MAGIC);
		if (next != NULL)
			next = VTAILQ_NEXT(next, list);
		if (next == NULL)
			next = VTAILQ_FIRST(&dom->refs);
		if (next == NULL)
			break;
		if (next->dir != NULL && VRT_Healthy(ctx, next->dir, NULL))
			break;
		/* if we do not find a healthy backend, use one with a director
		 * or, alternatively, whatever we can get
		 */
		if (alt == NULL || (alt->dir == NULL && next->dir != NULL))
			alt = next;
	} while (next != dom->current);

	dom->current = next;

	Lck_Unlock(&dom->mtx);

	if (next == NULL)
		next = alt;

	if (next == NULL)
		return (NULL);

	CHECK_OBJ(next, DYNAMIC_REF_MAGIC);
	if (next->dir != NULL)
		return (next->dir);

	// backend creation in progress
	Lck_Lock(&dom->mtx);
	while (next->dir == NULL)
		AZ(Lck_CondWait(&dom->resolve, &dom->mtx));
	Lck_Unlock(&dom->mtx);

	AN(next->dir);

	return (next->dir);
}

static VCL_BOOL v_matchproto_(vdi_healthy_f)
dom_healthy(VRT_CTX, VCL_BACKEND d, VCL_TIME *changed)
{
	struct dynamic_domain *dom;
	struct dynamic_ref *r, *alt;
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

	dom_wait_active(dom);

	do {
		/* One healthy backend is enough for the director to be
		 * healthy
		 */
		alt = NULL;
		VTAILQ_FOREACH(r, &dom->refs, list) {
			if (r->dir == NULL) {
				if (alt == NULL)
					alt = r;
				continue;
			}
			VRMB();
			CHECK_OBJ(r->dir, DIRECTOR_MAGIC);
			retval = VRT_Healthy(ctx, r->dir, &c);
			if (c > cc)
				cc = c;
			if (retval)
				break;
		}
		if (retval || IS_CLI())
			break;
		if (alt != NULL && alt->dir == NULL)
			AZ(Lck_CondWait(&dom->resolve, &dom->mtx));
	} while (alt != NULL);

	Lck_Unlock(&dom->mtx);

	if (changed != NULL)
		*changed = cc;

	dom->changed_cached = cc;
	dom->healthy_cached = retval;
	return (retval);
}

static void v_matchproto_(vdi_list_f)
dom_list(VRT_CTX, VCL_BACKEND dir, struct vsb *vsb, int pflag, int jflag)
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
		if (be == NULL)
			continue;
		VRMB();
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
dom_whitelisted(VRT_CTX, const struct dynamic_domain *dom,
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
ref_add(VRT_CTX, struct dynamic_ref *r)
{
	const struct dynamic_domain *dom;
	char addr[VTCP_ADDRBUFSIZE];
	char port[VTCP_PORTBUFSIZE];
	char vcl_name[1024];
	struct vrt_backend vrt;
	struct vrt_endpoint ep;
	VCL_BACKEND dir;

	CHECK_OBJ_NOTNULL(r, DYNAMIC_REF_MAGIC);
	dom = r->dom;
	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
	AZ(r->dir);
	AN(r->sa);

	VTCP_name(r->sa, addr, sizeof addr, port, sizeof port);

	INIT_OBJ(&vrt, VRT_BACKEND_MAGIC);

	switch (dom->obj->share) {
	case DIRECTOR:
		vrt.hosthdr = dom->obj->hosthdr;
		bprintf(vcl_name, "%s(%s:%s)", dom->obj->vcl_name, addr,
		    dom_port(dom));
		break;
	case HOST:
		vrt.hosthdr =
		    (dom->obj->hosthdr ? dom->obj->hosthdr : dom->addr);
		bprintf(vcl_name, "%s.%s(%s:%s%s%s)", dom->obj->vcl_name,
		    dom->addr, addr, dom_port(dom),
		    dom->authority ? "/" : "",
		    dom->authority ? dom->authority : "");
		break;
	default:
		INCOMPL();
	}

	if (dom->obj->via != NULL) {
		if (dom->authority != NULL)
			vrt.authority = dom->authority;
		else if (vrt.hosthdr != NULL)
			vrt.authority = vrt.hosthdr;
		else
			vrt.authority = dom->addr;
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

	switch (VSA_Get_Proto(r->sa)) {
	case AF_INET:
		ep.ipv4 = r->sa;
		break;
	case AF_INET6:
		ep.ipv6 = r->sa;
		break;
	default:
		WRONG("unexpected family");
	}
	vrt.endpoint = &ep;

	/* VRT_new_backend comes with a reference */
	dir = VRT_new_backend(ctx, &vrt, dom->obj->via);
	// for non-via, the sa from the backend is used
	if (dom->obj->via == NULL)
		VSA_free(&r->sa);
	VWMB();
	AZ(r->dir);
	r->dir = dir;

	DBG(ctx, dom, "new-backend %s", vrt.vcl_name);

	return;
}

static void
dom_update(struct dynamic_domain *dom, const struct res_cb *res,
    void *priv, vtim_real now)
{
	struct dynamic_domain *dom2;
	struct dynamic_ref *r, *r2;
	struct vrt_ctx ctx;
	uint8_t suckbuf[vsa_suckaddr_len];
	struct res_info ibuf[1] = {{ .suckbuf = suckbuf }};
	struct res_info *info;
	enum dynamic_share_e share;
	void *state = NULL;
	vtim_dur ttl = NAN;
	unsigned added = 0;

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = dom->obj->vcl;

	share = dom->obj->share;

	if (share != HOST)
		Lck_Lock(&dom->obj->domains_mtx);
	Lck_Lock(&dom->mtx);

	// refs first in oldrefs
	VTAILQ_SWAP(&dom->refs, &dom->oldrefs, dynamic_ref, list);
	VTAILQ_CONCAT(&dom->oldrefs, &dom->refs, list);
	assert(VTAILQ_EMPTY(&dom->refs));

	while ((info = res->result(ibuf, priv, &state)) != NULL) {
		if (! dom_whitelisted(&ctx, dom, info->sa))
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

		if (share == HOST)
			goto ref_add;

		/* search the director's other domains */
		AZ(r);
		Lck_AssertHeld(&dom->obj->domains_mtx);
		VRBT_FOREACH(dom2, dom_tree_head, &dom->obj->ref_domains) {
			if (dom2 == dom)
				continue;
			CHECK_OBJ_NOTNULL(dom2, DYNAMIC_DOMAIN_MAGIC);
			Lck_Lock(&dom2->mtx);
			VTAILQ_FOREACH(r, &dom2->refs, list) {
				// tolerate dup backend for in progress
				if (r->dir == NULL)
					continue;
				VRMB();
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

	  ref_add:
		added++;
		r = ref_new(dom);
		r->sa = VSA_Clone(info->sa);
		AZ(r->dir);
		VTAILQ_INSERT_TAIL(&dom->refs, r, list);
	}

	VTAILQ_FOREACH_SAFE(r, &dom->oldrefs, list, r2) {
		CHECK_OBJ_NOTNULL(r, DYNAMIC_REF_MAGIC);
		if (r == dom->current)
			dom->current = VTAILQ_FIRST(&dom->refs);
	}

	Lck_Unlock(&dom->mtx);
	if (share != HOST)
		Lck_Unlock(&dom->obj->domains_mtx);

	if (added) {
		VTAILQ_FOREACH(r, &dom->refs, list) {
			if (r->dir != NULL)
				continue;
			ref_add(&ctx, r);
		}
		Lck_Lock(&dom->mtx);
		AZ(pthread_cond_broadcast(&dom->resolve));
		Lck_Unlock(&dom->mtx);
	}

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
dom_lookup_thread(void *priv)
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

	Lck_Lock(&dom->mtx);
	// either from a VCL_EVENT_WARM or raced VCL_EVENT_COLD
	assert(dom->status == DYNAMIC_ST_STARTING ||
	    dom->status == DYNAMIC_ST_DONE);
	while (dom->status <= DYNAMIC_ST_ACTIVE) {
		Lck_Unlock(&dom->mtx);

		lookup = VTIM_real();
		if (lookup > dom->expires) {
			Lck_Lock(&obj->domains_mtx);
			if (lookup > dom->expires) {
				LOG(NULL, SLT_VCL_Log, dom, "%s", "timeout");
				dom->expires = HUGE_VAL;
				VRBT_REMOVE(dom_tree_head, &obj->ref_domains,
				    dom);
				VTAILQ_INSERT_TAIL(&obj->unref_domains, dom,
				    link.list);
			}
			Lck_Unlock(&obj->domains_mtx);
		}

		dynamic_timestamp(dom, "Lookup", lookup, 0., 0.);

		ret = res->lookup(obj->resolver_inst, dom->addr,
		    dom_port(dom), &res_priv);

		results = VTIM_real();
		dynamic_timestamp(dom, "Results", results, results - lookup,
		    results - lookup);

		if (ret == 0) {
			dom_update(dom, res, res_priv, results);
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
		if (dom->status <= DYNAMIC_ST_ACTIVE) {
			ret = Lck_CondWaitUntil(&dom->cond, &dom->mtx,
			    fmin(dom->deadline, dom->expires));
			assert(ret == 0 || ret == ETIMEDOUT);
		}
	}
	Lck_Unlock(&dom->mtx);

	assert(dom->status == DYNAMIC_ST_DONE);

	dynamic_timestamp(dom, "Done", VTIM_real(), 0., 0.);

	return (NULL);
}

static void
dom_free(struct dynamic_domain **domp, const char *why)
{
	struct dynamic_domain *dom;

	TAKE_OBJ_NOTNULL(dom, domp, DYNAMIC_DOMAIN_MAGIC);

	LOG(NULL, SLT_VCL_Log, dom, "deleted (%s)", why);
	VRT_DelDirector(&dom->dir);
}

static void
dynamic_gc_expired(struct vmod_dynamic_director *obj)
{
	struct dynamic_domain *dom;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	Lck_Lock(&obj->domains_mtx);
	while ((dom = VTAILQ_FIRST(&obj->unref_domains)) != NULL) {
		CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
		VTAILQ_REMOVE(&obj->unref_domains, dom, link.list);
		Lck_Unlock(&obj->domains_mtx);
		dom_free(&dom, "expired");
		Lck_Lock(&obj->domains_mtx);
	}
	Lck_Unlock(&obj->domains_mtx);
}

static void
dynamic_stop(struct vmod_dynamic_director *obj)
{

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	service_stop(obj);

	dynamic_gc_expired(obj);

	VRT_VCL_Allow_Discard(&obj->vclref);
}

static void
dynamic_start(VRT_CTX, struct vmod_dynamic_director *obj)
{
	char buf[128];

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	AZ(obj->vclref);

	bprintf(buf, "dynamic director %s", obj->vcl_name);
	/* name argument is being strdup()ed via REPLACE() */
	obj->vclref = VRT_VCL_Prevent_Discard(ctx, buf);
}

static struct dynamic_domain *
dynamic_search(struct vmod_dynamic_director *obj, const char *addr,
    const char *authority, const char *port)
{
	struct dynamic_domain dom[1];

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->domains_mtx);
	AN(addr);

	if (port != NULL)
		AN(*port);

	INIT_OBJ(dom, DYNAMIC_DOMAIN_MAGIC);
	dom->obj = obj;
	dom->addr = TRUST_ME(addr);
	dom->authority = TRUST_ME(authority);
	dom->port = TRUST_ME(port);

	return (VRBT_FIND(dom_tree_head, &obj->ref_domains, dom));
}

/*
 * NOTE:
 *
 * dom_release is _not_ registered as a director release callback, because we do
 * not add arbitraty references to other directors, but rather we create all
 * backends which we use solely through this director and are thus free to
 * release them later.
 *
 * We need to keep our backends around until the last reference to a domain is
 * lost, otherwise it would stop working
 */
static void v_matchproto_(vdi_release_f)
dom_release(VCL_BACKEND dir)
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
dom_destroy(VCL_BACKEND dir)
{
	struct dynamic_domain *dom;

	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, dir->priv, DYNAMIC_DOMAIN_MAGIC);

	DBG(NULL, dom, "%s", "destroy");

	dom_release(dir);

	AZ(dom->thread);
	assert(dom->status == DYNAMIC_ST_READY);
	assert(VTAILQ_EMPTY(&dom->refs));
	assert(VTAILQ_EMPTY(&dom->oldrefs));

	AZ(pthread_cond_destroy(&dom->resolve));
	AZ(pthread_cond_destroy(&dom->cond));
	Lck_Delete(&dom->mtx);
	REPLACE(dom->addr, NULL);
	REPLACE(dom->authority, NULL);
	REPLACE(dom->port, NULL);
	FREE_OBJ(dom);
}

static void v_matchproto_(vdi_event_f)
dom_event(VCL_BACKEND dir, enum vcl_event_e ev)
{
	struct dynamic_domain *dom;

	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, dir->priv, DYNAMIC_DOMAIN_MAGIC);

	DBG(NULL, dom, "event %d", ev);

	switch (ev) {
	case VCL_EVENT_WARM:
		// early start in _get
		if (dom->status == DYNAMIC_ST_STARTING ||
		    dom->status == DYNAMIC_ST_ACTIVE)
			break;
		assert(dom->status == DYNAMIC_ST_READY);
		dom->status = DYNAMIC_ST_STARTING;
		AZ(dom->thread);
		AZ(pthread_create(&dom->thread, NULL, dom_lookup_thread, dom));
		break;
	case VCL_EVENT_DISCARD:
		// discard after load with early start - XXX VTC
		if (dom->status == DYNAMIC_ST_READY)
			break;
		/* FALLTHROUGH */
	case VCL_EVENT_COLD:
		Lck_Lock(&dom->mtx);
		if (dom->status <= DYNAMIC_ST_ACTIVE)
			dom->status = DYNAMIC_ST_DONE;
		AZ(pthread_cond_signal(&dom->cond));
		AN(dom->thread);
		Lck_Unlock(&dom->mtx);

		AZ(pthread_join(dom->thread, NULL));
		dom->thread = 0;
		assert(dom->status == DYNAMIC_ST_DONE);
		dom->status = DYNAMIC_ST_READY;
		break;
	default:
		break;
	}
}

static const struct vdi_methods vmod_dynamic_methods[1] = {{
	.magic =	VDI_METHODS_MAGIC,
	.type =		"dynamic",
	.healthy =	dom_healthy,
	.resolve =	dom_resolve,
	.event =	dom_event,
	.destroy =	dom_destroy,
	.list =	dom_list
}};

struct dynamic_domain *
dynamic_get(VRT_CTX, struct vmod_dynamic_director *obj, const char *addr,
    const char *authority, const char *port)
{
	struct dynamic_domain *dom, *raced;
	VCL_TIME t;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_Lock(&obj->domains_mtx);
	AN(addr);

	t = ctx->now + obj->domain_usage_tmo;

	dom = dynamic_search(obj, addr, authority, port);
	if (dom != NULL) {
		if (t > dom->expires)
			dom->expires = t;
		Lck_Unlock(&obj->domains_mtx);
		return (dom);
	}

	Lck_Unlock(&obj->domains_mtx);

	ALLOC_OBJ(dom, DYNAMIC_DOMAIN_MAGIC);
	AN(dom);
	VTAILQ_INIT(&dom->refs);
	VTAILQ_INIT(&dom->oldrefs);
	REPLACE(dom->addr, addr);
	REPLACE(dom->authority, authority);
	REPLACE(dom->port, port);

	dom->obj = obj;
	dom->expires = t;

	Lck_New(&dom->mtx, lck_be);
	AZ(pthread_cond_init(&dom->cond, NULL));
	AZ(pthread_cond_init(&dom->resolve, NULL));

	dom->dir = VRT_AddDirector(ctx, vmod_dynamic_methods, dom,
	    "%s(%s:%s%s%s)", obj->vcl_name, addr, port,
	    authority ? "/" : "", authority ? authority : "");

	Lck_Lock(&obj->domains_mtx);
	raced = VRBT_INSERT(dom_tree_head, &obj->ref_domains, dom);
	Lck_Unlock(&obj->domains_mtx);

	if (raced) {
		dom_free(&dom, "raced");
		return (raced);
	}
	dom_event(dom->dir, VCL_EVENT_WARM);
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
    VCL_INT keep,
    VCL_STRING authority)
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
	VRBT_INIT(&obj->ref_domains);
	VTAILQ_INIT(&obj->unref_domains);
	VRBT_INIT(&obj->ref_services);
	VTAILQ_INIT(&obj->unref_services);
	REPLACE(obj->vcl_name, vcl_name);
	REPLACE(obj->port, port);
	REPLACE(obj->hosthdr, hosthdr);
	if (via)
		REPLACE(obj->authority, authority);

	obj->vcl_conf = VCL_Name(ctx->vcl);
	obj->vcl = ctx->vcl;
	obj->share = dynamic_share_parse(share_arg);
	obj->probe = probe;
	obj->whitelist = whitelist;
	obj->ttl = ttl;
	obj->retry_after = retry_after;
	obj->connect_tmo = connect_timeout;
	obj->first_byte_tmo = first_byte_timeout;
	obj->between_bytes_tmo = between_bytes_timeout;
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


	Lck_New(&obj->domains_mtx, lck_dir);
	Lck_New(&obj->services_mtx, lck_dir);

	VTAILQ_INSERT_TAIL(&objects, obj, list);
	*objp = obj;
}

VCL_VOID v_matchproto_()
vmod_director__fini(struct vmod_dynamic_director **objp)
{
	struct vmod_dynamic_director *obj;
	struct dynamic_domain *dom;

	ASSERT_CLI();
	AN(objp);
	obj = *objp;
	*objp = NULL;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	VTAILQ_REMOVE(&objects, obj, list);

	service_fini(obj);

	while ((dom = VRBT_ROOT(&obj->ref_domains)) != NULL) {
		VRBT_REMOVE(dom_tree_head, &obj->ref_domains, dom);
		dom_free(&dom, "fini");
	}

	assert(VRBT_EMPTY(&obj->ref_domains));
	assert(VTAILQ_EMPTY(&obj->unref_domains));
	assert(VRBT_EMPTY(&obj->ref_services));
	assert(VTAILQ_EMPTY(&obj->unref_services));
	REPLACE(obj->vcl_name, NULL);
	REPLACE(obj->port, NULL);
	REPLACE(obj->hosthdr, NULL);
	REPLACE(obj->authority, NULL);

	Lck_Delete(&obj->domains_mtx);
	Lck_Delete(&obj->services_mtx);

	FREE_OBJ(obj);
}

VCL_BACKEND v_matchproto_(td_dynamic_director_backend)
vmod_director_backend(VRT_CTX, struct vmod_dynamic_director *obj,
    VCL_STRING host, VCL_STRING port, VCL_STRING authority)
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

	if (authority == NULL)
		authority = obj->authority;

	dom = dynamic_get(ctx, obj, host, authority, port);
	AN(dom);

	return (dom->dir);
}

VCL_VOID v_matchproto_(td_dynamic_director_debug)
vmod_director_debug(VRT_CTX, struct vmod_dynamic_director *obj,
    VCL_BOOL enable)
{

	(void)ctx;
	obj->debug = enable;
}
