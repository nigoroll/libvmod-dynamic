/*-
 * Copyright (c) 2015-2016 Varnish Software AS
 * All rights reserved.
 *
 * Author: Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
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
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include <vcl.h>
#include <vrt.h>
#include <vsa.h>
#include <vtim.h>

#include <cache/cache.h>
#include <cache/cache_director.h>

#include "vcc_if.h"
#include "vmod_named.h"

#define LOG(ctx, slt, dom, fmt, ...)				\
	do {							\
		if ((ctx)->vsl != NULL)				\
			VSLb((ctx)->vsl, slt,			\
			    "vmod-named: %s %s %s " fmt,	\
			    (dom)->obj->vcl_conf,		\
			    (dom)->obj->vcl_name, (dom)->addr,	\
			    __VA_ARGS__);			\
		else						\
			VSL(slt, 0,				\
			    "vmod-named: %s %s %s " fmt, 	\
			    (dom)->obj->vcl_conf,		\
			    (dom)->obj->vcl_name, (dom)->addr,	\
			    __VA_ARGS__);			\
	} while (0)

/*--------------------------------------------------------------------
 * Global data structures
 *
 * No locking required, mutated only by the CLI thread with guarantees that
 * they can't be accessed at the same time.
 */

struct vmod_named_head objects = VTAILQ_HEAD_INITIALIZER(objects);

static struct VSC_C_lck *lck_dir, *lck_be;

static unsigned loadcnt = 0;

static const struct gethdr_s HDR_REQ_HOST = { HDR_REQ, "\005Host:"};
static const struct gethdr_s HDR_BEREQ_HOST = { HDR_BEREQ, "\005Host:"};

/*--------------------------------------------------------------------
 * Director implementation
 */

static const struct director * __match_proto__(vdi_resolve_f)
named_resolve(const struct director *d, struct worker *wrk,
    struct busyobj *bo)
{
	struct named_domain *dom;
	struct named_ref *next;
	double deadline;
	int ret;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, d->priv, NAMED_DOMAIN_MAGIC);
	(void)wrk;
	(void)bo;

	Lck_Lock(&dom->mtx);

	if (dom->status < NAMED_ST_ACTIVE) {
		deadline = VTIM_real() + dom->obj->first_lookup_tmo;
		ret = Lck_CondWait(&dom->resolve, &dom->mtx, deadline);
		assert(ret == 0 || ret == ETIMEDOUT);
	}

	if (dom->status > NAMED_ST_ACTIVE) {
		Lck_Unlock(&dom->mtx);
		return (NULL);
	}

	next = dom->current;

	do {
		if (next != NULL)
			next = VTAILQ_NEXT(next, list);
		if (next == NULL)
			next = VTAILQ_FIRST(&dom->refs);
	} while (next != dom->current &&
	    !next->be->dir->healthy(next->be->dir, NULL, NULL));

	dom->current = next;

	if (next != NULL &&
	    !next->be->dir->healthy(next->be->dir, NULL, NULL))
		next = NULL;

	Lck_Unlock(&dom->mtx);

	assert(next == NULL || next->be->dir != NULL);
	return (next == NULL ? NULL : next->be->dir);
}

static unsigned __match_proto__(vdi_healthy_f)
named_healthy(const struct director *d, const struct busyobj *bo,
    double *changed)
{
	struct named_domain *dom;
	struct named_ref *r;
	unsigned retval = 0;
	double c;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, d->priv, NAMED_DOMAIN_MAGIC);

	Lck_Lock(&dom->mtx);

	if (changed != NULL)
		*changed = 0;

	/* One healthy backend is enough for the director to be healthy */
	VTAILQ_FOREACH(r, &dom->refs, list) {
		CHECK_OBJ_NOTNULL(r->be->dir, DIRECTOR_MAGIC);
		AN(r->be->dir->healthy);
		retval = r->be->dir->healthy(r->be->dir, bo, &c);
		if (changed != NULL && c > *changed)
			*changed = c;
		if (retval)
			break;
	}

	Lck_Unlock(&dom->mtx);

	return (retval);
}

/*--------------------------------------------------------------------
 * Background job
 */

static void
named_del(VRT_CTX, struct named_ref *r)
{
	struct named_domain *dom;
	struct named_backend *b;

	AN(r);
	CHECK_OBJ_ORNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r->dom, NAMED_DOMAIN_MAGIC);

	b = r->be;
	AN(b);
	CHECK_OBJ_NOTNULL(b->dir, DIRECTOR_MAGIC);

	dom = r->dom;

	if (ctx != NULL) {
		Lck_AssertHeld(&dom->mtx);
		Lck_AssertHeld(&dom->obj->mtx);
	}

	if (r == dom->current)
		dom->current = VTAILQ_NEXT(r, list);

	VTAILQ_REMOVE(&dom->refs, r, list);
	free(r);

	AN(b->refcount);
	b->refcount--;

	if (b->refcount > 0)
		return;

	VTAILQ_REMOVE(&dom->obj->backends, b, list);
	if (ctx) {
		AN(ctx->vcl);
		VRT_delete_backend(ctx, &b->dir);
	}
	free(b->vcl_name);
	free(b->ip_addr);
	free(b->ip_suckaddr);
	free(b);
}

static void
named_ref(struct named_domain *dom, struct named_backend *b)
{
	struct named_ref *r;

	r = malloc(sizeof *r);
	memset(r, 0, sizeof *r);
	AN(r);
	r->dom = dom;
	r->be = b;
	r->mark = dom->mark;
	b->refcount++;
	VTAILQ_INSERT_TAIL(&dom->refs, r, list);
}

static unsigned
named_find(struct named_domain *dom, struct suckaddr *sa)
{
	struct named_ref *r;
	struct named_backend *b;

	CHECK_OBJ_NOTNULL(dom, NAMED_DOMAIN_MAGIC);
	CHECK_OBJ_NOTNULL(dom->obj, VMOD_NAMED_DIRECTOR_MAGIC);

	/* search this director's backends */
	VTAILQ_FOREACH(r, &dom->refs, list) {
		if (r->mark == dom->mark)
			continue;

		b = r->be;
		CHECK_OBJ_NOTNULL(b->dir, DIRECTOR_MAGIC);
		if (!VSA_Compare(b->ip_suckaddr, sa)) {
			r->mark = dom->mark;
			return (1);
		}
	}

	/* search the rest of the backends */
	VTAILQ_FOREACH(b, &dom->obj->backends, list) {
		CHECK_OBJ_NOTNULL(b->dir, DIRECTOR_MAGIC);
		if (!VSA_Compare(b->ip_suckaddr, sa)) {
			named_ref(dom, b);
			return (1);
		}
	}

	return (0);
}

static unsigned
named_add(VRT_CTX, struct named_domain *dom, struct suckaddr *sa)
{
	struct vrt_backend vrt;
	struct named_backend *b;
	struct vsb *vsb;
	const unsigned char *ptr = NULL;
	char ip[INET6_ADDRSTRLEN];
	int af;

	CHECK_OBJ_NOTNULL(dom, NAMED_DOMAIN_MAGIC);
	CHECK_OBJ_NOTNULL(dom->obj, VMOD_NAMED_DIRECTOR_MAGIC);
	Lck_AssertHeld(&dom->mtx);
	Lck_AssertHeld(&dom->obj->mtx);

	if (named_find(dom, sa))
		return (0);

	b = malloc(sizeof *b);
	AN(b);
	memset(b, 0, sizeof *b);
	b->ip_suckaddr = sa;

	af = VRT_VSA_GetPtr(sa, &ptr);
	AN(ptr);
	AN(inet_ntop(af, ptr, ip, sizeof ip));
	b->ip_addr = strdup(ip);
	AN(b->ip_addr);

	vsb = VSB_new_auto();
	AN(vsb);
	VSB_printf(vsb, "%s(%s)", dom->obj->vcl_name, b->ip_addr);
	AZ(VSB_finish(vsb));

	b->vcl_name = strdup(VSB_data(vsb));
	AN(b->vcl_name);
	VSB_delete(vsb);

	INIT_OBJ(&vrt, VRT_BACKEND_MAGIC);
	vrt.port = dom->port;
	vrt.hosthdr = dom->obj->hosthdr;
	vrt.vcl_name = b->vcl_name;
	vrt.probe = dom->obj->probe;
	vrt.connect_timeout = dom->obj->connect_tmo;
	vrt.first_byte_timeout = dom->obj->first_byte_tmo;
	vrt.between_bytes_timeout = dom->obj->between_bytes_tmo;

	switch (af) {
	case AF_INET:
		vrt.ipv4_suckaddr = sa;
		vrt.ipv4_addr = b->ip_addr;
		break;
	case AF_INET6:
		vrt.ipv6_suckaddr = sa;
		vrt.ipv6_addr = b->ip_addr;
		break;
	default:
		WRONG("unexpected family");
	}

	b->dir = VRT_new_backend(ctx, &vrt);
	AN(b->dir);

	named_ref(dom, b);

	VTAILQ_INSERT_TAIL(&dom->obj->backends, b, list);
	return (1);
}

static void
named_update(struct named_domain *dom, struct addrinfo *addr)
{
	struct suckaddr *sa;
	struct named_ref *r, *r2;
	struct vrt_ctx ctx;
	VCL_ACL acl;
	unsigned match;

	AN(addr);

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = dom->obj->vcl;

	Lck_Lock(&dom->obj->mtx);
	Lck_Lock(&dom->mtx);

	dom->mark++;
	acl = dom->obj->whitelist;

	while (addr) {
		switch (addr->ai_family) {
		case AF_INET:
		case AF_INET6:
			sa = malloc(vsa_suckaddr_len);
			AN(sa);
			AN(VSA_Build(sa, addr->ai_addr, addr->ai_addrlen));
			match = acl != NULL ? VRT_acl_match(&ctx, acl, sa) : 1;
			if (!match)
				LOG(&ctx, SLT_Error, dom, "%s", "mismatch");
			if (!match || !named_add(&ctx, dom, sa))
				free(sa);
		}
		addr = addr->ai_next;
	}

	VTAILQ_FOREACH_SAFE(r, &dom->refs, list, r2)
		if (r->mark != dom->mark)
			named_del(&ctx, r);

	Lck_Unlock(&dom->mtx);
	Lck_Unlock(&dom->obj->mtx);
}

static void*
named_lookup_thread(void *obj)
{
	struct named_domain *dom;
	struct addrinfo hints, *res;
	struct vrt_ctx ctx;
	double deadline;
	int ret;

	CAST_OBJ_NOTNULL(dom, obj, NAMED_DOMAIN_MAGIC);
	INIT_OBJ(&ctx, VRT_CTX_MAGIC);

	memset(&hints, 0, sizeof hints);
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;

	while (dom->obj->active && dom->status <= NAMED_ST_ACTIVE) {

		ret = getaddrinfo(dom->addr, dom->obj->port, &hints, &res);

		if (ret == 0) {
			named_update(dom, res);
			freeaddrinfo(res);
		}
		else
			LOG(&ctx, SLT_Error, dom, "getaddrinfo %d (%s)",
			    ret, gai_strerror(ret));

		Lck_Lock(&dom->mtx);

		if (dom->status == NAMED_ST_READY) {
			AZ(pthread_cond_broadcast(&dom->resolve));
			dom->status = NAMED_ST_ACTIVE;
		}

		/* Check status again after the blocking call */
		if (!dom->obj->active || dom->status == NAMED_ST_STALE) {
			Lck_Unlock(&dom->mtx);
			break;
		}

		deadline = VTIM_real() + dom->obj->ttl;
		ret = Lck_CondWait(&dom->cond, &dom->mtx, deadline);
		assert(ret == 0 || ret == ETIMEDOUT);

		Lck_Unlock(&dom->mtx);
	}

	dom->status = NAMED_ST_DONE;

	return (NULL);
}

static void
named_free(VRT_CTX, struct named_domain *dom)
{

	CHECK_OBJ_ORNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(dom, NAMED_DOMAIN_MAGIC);
	AZ(dom->thread);
	assert(dom->status == NAMED_ST_READY);

	if (ctx != NULL) {
		Lck_AssertHeld(&dom->obj->mtx);
		LOG(ctx, SLT_VCL_Log, dom, "%s", "deleted");
	}

	Lck_Lock(&dom->mtx);
	while (!VTAILQ_EMPTY(&dom->refs))
		named_del(ctx, VTAILQ_FIRST(&dom->refs));
	Lck_Unlock(&dom->mtx);

	AZ(pthread_cond_destroy(&dom->resolve));
	AZ(pthread_cond_destroy(&dom->cond));
	Lck_Delete(&dom->mtx);
	free(dom->addr);
	FREE_OBJ(dom);
}

static void
named_stop(struct vmod_named_director *obj)
{
	struct named_domain *dom, *d2;
	struct vrt_ctx ctx;

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);

	Lck_Lock(&obj->mtx);
	VTAILQ_FOREACH(dom, &obj->active_domains, list) {
		CHECK_OBJ_NOTNULL(dom, NAMED_DOMAIN_MAGIC);
		Lck_Lock(&dom->mtx);
		AN(dom->thread);
		AZ(pthread_cond_signal(&dom->cond));
		Lck_Unlock(&dom->mtx);
	}

	/* NB: After a call to pthread_join we know for sure that the only
	 * potential contender stopped. Therefore locking is no longer
	 * required to access a (struct named_domain *)->status.
	 */

	VTAILQ_FOREACH(dom, &obj->active_domains, list) {
		CHECK_OBJ_NOTNULL(dom, NAMED_DOMAIN_MAGIC);
		AZ(pthread_join(dom->thread, NULL));
		assert(dom->status == NAMED_ST_DONE);
		dom->thread = 0;
		dom->status = NAMED_ST_READY;
	}

	VTAILQ_FOREACH_SAFE(dom, &obj->purged_domains, list, d2) {
		CHECK_OBJ_NOTNULL(dom, NAMED_DOMAIN_MAGIC);
		Lck_Lock(&dom->mtx);
		assert(dom->status == NAMED_ST_STALE ||
		    dom->status == NAMED_ST_DONE);
		Lck_Unlock(&dom->mtx);
		AZ(pthread_join(dom->thread, NULL));
		assert(dom->status == NAMED_ST_DONE);
		dom->status = NAMED_ST_READY;
		named_free(NULL, dom);
		VTAILQ_REMOVE(&dom->obj->purged_domains, dom, list);
	}

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = obj->vcl;
	VRT_rel_vcl(&ctx, &obj->vclref);
	Lck_Unlock(&obj->mtx);
}

static void
named_start(struct vmod_named_director *obj)
{
	struct named_domain *dom;
	struct vrt_ctx ctx;

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);
	AZ(obj->vclref);

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = obj->vcl;
	/* XXX: name it "named director %s" instead */
	obj->vclref = VRT_ref_vcl(&ctx, "vmod named");

	Lck_Lock(&obj->mtx);
	VTAILQ_FOREACH(dom, &obj->active_domains, list) {
		CHECK_OBJ_NOTNULL(dom, NAMED_DOMAIN_MAGIC);
		assert(dom->status == NAMED_ST_READY);
		AZ(dom->thread);
		AZ(pthread_create(&dom->thread, NULL, &named_lookup_thread,
		    dom));
	}
	Lck_Unlock(&obj->mtx);
}

static struct named_domain *
named_search(VRT_CTX, struct vmod_named_director *obj, const char *addr)
{
	struct named_domain *dom, *d, *d2;

	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);
	AN(addr);

	dom = NULL;
	VTAILQ_FOREACH_SAFE(d, &obj->active_domains, list, d2) {
		CHECK_OBJ_NOTNULL(d, NAMED_DOMAIN_MAGIC);
		if (!strcmp(d->addr, addr)) {
			AZ(dom);
			dom = d;
		}
		if (dom != d && d->status == NAMED_ST_ACTIVE &&
		    obj->domain_usage_tmo > 0 &&
		    ctx->now - d->last_used > obj->domain_usage_tmo) {
			LOG(ctx, SLT_VCL_Log, d, "%s", "timeout");
			Lck_Lock(&d->mtx);
			d->status = NAMED_ST_STALE;
			AZ(pthread_cond_signal(&d->cond));
			Lck_Unlock(&d->mtx);
			VTAILQ_REMOVE(&d->obj->active_domains, d, list);
			VTAILQ_INSERT_TAIL(&d->obj->purged_domains, d, list);
		}
	}

	VTAILQ_FOREACH_SAFE(d, &obj->purged_domains, list, d2) {
		CHECK_OBJ_NOTNULL(d, NAMED_DOMAIN_MAGIC);
		if (d->status == NAMED_ST_DONE) {
			AZ(pthread_join(d->thread, NULL));
			Lck_Lock(&d->mtx);
			d->thread = 0;
			d->status = NAMED_ST_READY;
			Lck_Unlock(&d->mtx);
			named_free(ctx, d);
			VTAILQ_REMOVE(&dom->obj->purged_domains, d, list);
		}
	}

	return (dom);
}

static struct named_domain *
named_get(VRT_CTX, struct vmod_named_director *obj, const char *addr)
{
	struct named_domain *dom;

	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);
	AN(addr);

	dom = named_search(ctx, obj, addr);
	if (dom != NULL)
		return (dom);

	ALLOC_OBJ(dom, NAMED_DOMAIN_MAGIC);
	AN(dom);
	VTAILQ_INIT(&dom->refs);
	REPLACE(dom->addr, addr);
	dom->port = obj->port;
	dom->obj = obj;

	INIT_OBJ(&dom->dir, DIRECTOR_MAGIC);
	dom->dir.name = "dns";
	dom->dir.vcl_name = dom->obj->vcl_name;
	dom->dir.healthy = named_healthy;
	dom->dir.resolve = named_resolve;
	dom->dir.priv = dom;

	Lck_New(&dom->mtx, lck_be);
	AZ(pthread_cond_init(&dom->cond, NULL));
	AZ(pthread_cond_init(&dom->resolve, NULL));

	AZ(pthread_create(&dom->thread, NULL, &named_lookup_thread, dom));

	VTAILQ_INSERT_TAIL(&obj->active_domains, dom, list);

	return (dom);
}

/*--------------------------------------------------------------------
 * VMOD interfaces
 */

int __match_proto__(vmod_event_f)
vmod_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	struct vmod_named_director *obj;
	unsigned active;

	(void)priv;

	ASSERT_CLI();
	AN(ctx);
	AN(ctx->vcl);

	if (e == VCL_EVENT_LOAD) {
		if (loadcnt == 0) {
			lck_dir = Lck_CreateClass("named.director");
			lck_be = Lck_CreateClass("named.backend");
			AN(lck_dir);
			AN(lck_be);
		}
		loadcnt++;
		return (0);
	}

	if (e == VCL_EVENT_DISCARD) {
		assert(loadcnt > 0);
		loadcnt--;
		if (loadcnt == 0) {
			VSM_Free(lck_dir);
			VSM_Free(lck_be);
		}
		return (0);
	}

	if (e == VCL_EVENT_USE)
		return (0);

	active = e == VCL_EVENT_WARM ? 1 : 0;

	/* No locking required for the fields obj->active and obj->vcl */
	VTAILQ_FOREACH(obj, &objects, list)
		if (obj->vcl == ctx->vcl) {
			xxxassert(obj->active != active);
			obj->active = active;
			if (active)
				named_start(obj);
			else
				named_stop(obj);
		}

	return (0);
}

VCL_VOID __match_proto__()
vmod_director__init(VRT_CTX,
    struct vmod_named_director **objp,
    const char *vcl_name,
    VCL_STRING port,
    VCL_STRING hosthdr,
    VCL_PROBE probe,
    VCL_ACL whitelist,
    VCL_DURATION ttl,
    VCL_DURATION connect_timeout,
    VCL_DURATION first_byte_timeout,
    VCL_DURATION between_bytes_timeout,
    VCL_DURATION domain_usage_timeout,
    VCL_DURATION first_lookup_timeout)
{
	struct vmod_named_director *obj;

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(objp);
	AZ(*objp);
	AN(vcl_name);
	AN(port);
	CHECK_OBJ_ORNULL(probe, VRT_BACKEND_PROBE_MAGIC);
	CHECK_OBJ_ORNULL(whitelist, VRT_ACL_MAGIC);
	xxxassert(ttl > 0);

	ALLOC_OBJ(obj, VMOD_NAMED_DIRECTOR_MAGIC);
	AN(obj);
	VTAILQ_INIT(&obj->active_domains);
	VTAILQ_INIT(&obj->purged_domains);
	VTAILQ_INIT(&obj->backends);
	REPLACE(obj->vcl_name, vcl_name);
	REPLACE(obj->port, port);

	obj->vcl_conf = VCL_Name(ctx->vcl);
	obj->vcl = ctx->vcl;
	obj->active = 0;
	obj->hosthdr = hosthdr;
	obj->probe = probe;
	obj->whitelist = whitelist;
	obj->ttl = ttl;
	obj->connect_tmo = connect_timeout;
	obj->first_byte_tmo = first_byte_timeout;
	obj->between_bytes_tmo = between_bytes_timeout;
	obj->domain_usage_tmo = domain_usage_timeout;
	obj->first_lookup_tmo = first_lookup_timeout;

	Lck_New(&obj->mtx, lck_dir);

	VTAILQ_INSERT_TAIL(&objects, obj, list);
	*objp = obj;
}

VCL_VOID __match_proto__()
vmod_director__fini(struct vmod_named_director **objp)
{
	struct vmod_named_director *obj;

	ASSERT_CLI();
	AN(objp);
	obj = *objp;
	*objp = NULL;

	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);
	AZ(obj->active);

	VTAILQ_REMOVE(&objects, obj, list);

	/* Backends will be deleted by the VCL, pass a NULL struct ctx */
	while (!VTAILQ_EMPTY(&obj->purged_domains)) {
		named_free(NULL, VTAILQ_FIRST(&obj->purged_domains));
		VTAILQ_REMOVE(&obj->purged_domains,
		    VTAILQ_FIRST(&obj->purged_domains), list);
	}

	while (!VTAILQ_EMPTY(&obj->active_domains)) {
		named_free(NULL, VTAILQ_FIRST(&obj->active_domains));
		VTAILQ_REMOVE(&obj->active_domains,
		    VTAILQ_FIRST(&obj->active_domains), list);
	}

	assert(VTAILQ_EMPTY(&obj->backends));

	Lck_Delete(&obj->mtx);
	free(obj->vcl_name);
	FREE_OBJ(obj);
}

VCL_BACKEND __match_proto__(td_named_director_backend)
vmod_director_backend(VRT_CTX, struct vmod_named_director *obj, VCL_STRING host)
{
	struct named_domain *dom;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);

	if ((host == NULL || *host == '\0') && ctx->http_bereq != NULL)
		host = VRT_GetHdr(ctx, &HDR_BEREQ_HOST);

	if ((host == NULL || *host == '\0') && ctx->http_req != NULL)
		host = VRT_GetHdr(ctx, &HDR_REQ_HOST);

	if (host == NULL || *host == '\0')
		return (NULL);

	Lck_Lock(&obj->mtx);
	dom = named_get(ctx, obj, host);
	AN(dom);
	dom->last_used = ctx->now;
	Lck_Unlock(&obj->mtx);

	return (&dom->dir);
}
