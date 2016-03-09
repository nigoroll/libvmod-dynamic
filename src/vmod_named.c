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

#define LOG(ctx, slt, dir, fmt, ...)				\
	do {							\
		if ((ctx)->vsl != NULL)				\
			VSLb((ctx)->vsl, slt,			\
			    "vmod-named: %s %s %s " fmt,	\
			    (dir)->obj->vcl_conf,		\
			    (dir)->obj->vcl_name, (dir)->addr,	\
			    __VA_ARGS__);			\
		else						\
			VSL(slt, 0,				\
			    "vmod-named: %s %s %s " fmt, 	\
			    (dir)->obj->vcl_conf,		\
			    (dir)->obj->vcl_name, (dir)->addr,	\
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
vmod_dns_resolve(const struct director *d, struct worker *wrk,
    struct busyobj *bo)
{
	struct dns_director *dir;
	struct dir_entry *next;
	double deadline;
	int ret;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dir, d->priv, DNS_DIRECTOR_MAGIC);
	(void)wrk;
	(void)bo;

	Lck_Lock(&dir->mtx);

	if (dir->status < NAMED_ST_ACTIVE) {
		deadline = VTIM_real() + dir->obj->first_tmo;
		ret = Lck_CondWait(&dir->resolve, &dir->mtx, deadline);
		assert(ret == 0 || ret == ETIMEDOUT);
	}

	if (dir->status > NAMED_ST_ACTIVE) {
		Lck_Unlock(&dir->mtx);
		return (NULL);
	}

	next = dir->current;

	do {
		if (next != NULL)
			next = VTAILQ_NEXT(next, dir_list);
		if (next == NULL)
			next = VTAILQ_FIRST(&dir->entries);
	} while (next != dir->current &&
	    !next->entry->backend->healthy(next->entry->backend, NULL, NULL));

	dir->current = next;

	if (next != NULL &&
	    !next->entry->backend->healthy(next->entry->backend, NULL, NULL))
		next = NULL;

	Lck_Unlock(&dir->mtx);

	assert(next == NULL || next->entry->backend != NULL);
	return (next == NULL ? NULL : next->entry->backend);
}

static unsigned __match_proto__(vdi_healthy_f)
vmod_dns_healthy(const struct director *d, const struct busyobj *bo,
    double *changed)
{
	struct dns_director *dir;
	struct dir_entry *e;
	unsigned retval = 0;
	double c;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dir, d->priv, DNS_DIRECTOR_MAGIC);

	Lck_Lock(&dir->mtx);

	if (changed != NULL)
		*changed = 0;

	/* One healthy backend is enough for the director to be healthy */
	VTAILQ_FOREACH(e, &dir->entries, dir_list) {
		CHECK_OBJ_NOTNULL(e->entry->backend, DIRECTOR_MAGIC);
		AN(e->entry->backend->healthy);
		retval = e->entry->backend->healthy(e->entry->backend, bo, &c);
		if (changed != NULL && c > *changed)
			*changed = c;
		if (retval)
			break;
	}

	Lck_Unlock(&dir->mtx);

	return (retval);
}

/*--------------------------------------------------------------------
 * Background job
 */

static void
vmod_dns_del(VRT_CTX, struct dir_entry *e)
{
	struct dns_director *dir;
	struct dns_entry *b;

	AN(e);
	CHECK_OBJ_ORNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(e->dir, DNS_DIRECTOR_MAGIC);

	b = e->entry;
	AN(b);
	CHECK_OBJ_NOTNULL(b->backend, DIRECTOR_MAGIC);

	dir = e->dir;

	if (ctx != NULL) {
		Lck_AssertHeld(&dir->mtx);
		Lck_AssertHeld(&dir->obj->mtx);
	}

	if (e == dir->current)
		dir->current = VTAILQ_NEXT(e, dir_list);

	VTAILQ_REMOVE(&dir->entries, e, dir_list);
	free(e);

	AN(b->refcount);
	b->refcount--;

	if (b->refcount > 0)
		return;

	VTAILQ_REMOVE(&dir->obj->entries, b, dns_list);
	if (ctx) {
		AN(ctx->vcl);
		VRT_delete_backend(ctx, &b->backend);
	}
	free(b->vcl_name);
	free(b->ip_addr);
	free(b->ip_suckaddr);
	free(b);
}

static void
vmod_dns_ref(struct dns_director *dir, struct dns_entry *b)
{
	struct dir_entry *e;

	e = malloc(sizeof *e);
	memset(e, 0, sizeof *e);
	AN(e);
	e->dir = dir;
	e->entry = b;
	e->mark = dir->mark;
	b->refcount++;
	VTAILQ_INSERT_TAIL(&dir->entries, e, dir_list);
}

static unsigned
vmod_dns_find(struct dns_director *dir, struct suckaddr *sa)
{
	struct dir_entry *e;
	struct dns_entry *b;

	CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
	CHECK_OBJ_NOTNULL(dir->obj, VMOD_NAMED_DIRECTOR_MAGIC);

	/* search this director's backends */
	VTAILQ_FOREACH(e, &dir->entries, dir_list) {
		if (e->mark == dir->mark)
			continue;

		b = e->entry;
		CHECK_OBJ_NOTNULL(b->backend, DIRECTOR_MAGIC);
		if (!VSA_Compare(b->ip_suckaddr, sa)) {
			e->mark = dir->mark;
			return (1);
		}
	}

	/* search the rest of the backends */
	VTAILQ_FOREACH(b, &dir->obj->entries, dns_list) {
		CHECK_OBJ_NOTNULL(b->backend, DIRECTOR_MAGIC);
		if (!VSA_Compare(b->ip_suckaddr, sa)) {
			vmod_dns_ref(dir, b);
			return (1);
		}
	}

	return (0);
}

static unsigned
vmod_dns_add(VRT_CTX, struct dns_director *dir, struct suckaddr *sa)
{
	struct vrt_backend vrt;
	struct dns_entry *b;
	struct vsb *vsb;
	const unsigned char *ptr = NULL;
	char ip[INET6_ADDRSTRLEN];
	int af;

	CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
	CHECK_OBJ_NOTNULL(dir->obj, VMOD_NAMED_DIRECTOR_MAGIC);
	Lck_AssertHeld(&dir->mtx);
	Lck_AssertHeld(&dir->obj->mtx);

	if (vmod_dns_find(dir, sa))
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
	VSB_printf(vsb, "%s(%s)", dir->obj->vcl_name, b->ip_addr);
	AZ(VSB_finish(vsb));

	b->vcl_name = strdup(VSB_data(vsb));
	AN(b->vcl_name);
	VSB_delete(vsb);

	INIT_OBJ(&vrt, VRT_BACKEND_MAGIC);
	vrt.port = dir->port;
	vrt.hosthdr = dir->addr;
	vrt.vcl_name = b->vcl_name;
	vrt.probe = dir->obj->probe;

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

	b->backend = VRT_new_backend(ctx, &vrt);
	AN(b->backend);

	vmod_dns_ref(dir, b);

	VTAILQ_INSERT_TAIL(&dir->obj->entries, b, dns_list);
	return (1);
}

static void
vmod_dns_update(struct dns_director *dir, struct addrinfo *addr)
{
	struct suckaddr *sa;
	struct dir_entry *e, *e2;
	struct vrt_ctx ctx;
	VCL_ACL acl;
	unsigned match;

	AN(addr);

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = dir->obj->vcl;

	Lck_Lock(&dir->obj->mtx);
	Lck_Lock(&dir->mtx);

	dir->mark++;
	acl = dir->obj->whitelist;

	while (addr) {
		switch (addr->ai_family) {
		case AF_INET:
		case AF_INET6:
			sa = malloc(vsa_suckaddr_len);
			AN(sa);
			AN(VSA_Build(sa, addr->ai_addr, addr->ai_addrlen));
			match = acl != NULL ? VRT_acl_match(&ctx, acl, sa) : 1;
			if (!match)
				LOG(&ctx, SLT_Error, dir, "%s", "mismatch");
			if (!match || !vmod_dns_add(&ctx, dir, sa))
				free(sa);
		}
		addr = addr->ai_next;
	}

	VTAILQ_FOREACH_SAFE(e, &dir->entries, dir_list, e2)
		if (e->mark != dir->mark)
			vmod_dns_del(&ctx, e);

	Lck_Unlock(&dir->mtx);
	Lck_Unlock(&dir->obj->mtx);
}

static void*
vmod_dns_lookup_thread(void *obj)
{
	struct dns_director *dir;
	struct addrinfo hints, *res;
	struct vrt_ctx ctx;
	double deadline;
	int ret;

	CAST_OBJ_NOTNULL(dir, obj, DNS_DIRECTOR_MAGIC);
	INIT_OBJ(&ctx, VRT_CTX_MAGIC);

	memset(&hints, 0, sizeof hints);
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;

	while (dir->obj->active && dir->status <= NAMED_ST_ACTIVE) {

		ret = getaddrinfo(dir->addr, dir->obj->port, &hints, &res);

		if (ret == 0) {
			vmod_dns_update(dir, res);
			freeaddrinfo(res);
		}
		else
			LOG(&ctx, SLT_Error, dir, "getaddrinfo %d (%s)",
			    ret, gai_strerror(ret));

		Lck_Lock(&dir->mtx);

		if (dir->status == NAMED_ST_READY) {
			AZ(pthread_cond_broadcast(&dir->resolve));
			dir->status = NAMED_ST_ACTIVE;
		}

		/* Check status again after the blocking call */
		if (!dir->obj->active || dir->status == NAMED_ST_STALE) {
			Lck_Unlock(&dir->mtx);
			break;
		}

		deadline = VTIM_real() + dir->obj->ttl;
		ret = Lck_CondWait(&dir->cond, &dir->mtx, deadline);
		assert(ret == 0 || ret == ETIMEDOUT);

		Lck_Unlock(&dir->mtx);
	}

	dir->status = NAMED_ST_DONE;

	return (NULL);
}

static void
vmod_dns_free(VRT_CTX, struct dns_director *dir)
{

	CHECK_OBJ_ORNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
	AZ(dir->thread);
	assert(dir->status == NAMED_ST_READY);


	if (ctx != NULL) {
		Lck_AssertHeld(&dir->obj->mtx);
		LOG(ctx, SLT_VCL_Log, dir, "%s", "deleted");
	}

	Lck_Lock(&dir->mtx);
	while (!VTAILQ_EMPTY(&dir->entries))
		vmod_dns_del(ctx, VTAILQ_FIRST(&dir->entries));
	Lck_Unlock(&dir->mtx);

	AZ(pthread_cond_destroy(&dir->resolve));
	AZ(pthread_cond_destroy(&dir->cond));
	Lck_Delete(&dir->mtx);
	free(dir->addr);
	FREE_OBJ(dir);
}

static void
vmod_dns_stop(struct vmod_named_director *obj)
{
	struct dns_director *dir, *d2;
	struct vrt_ctx ctx;

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);

	Lck_Lock(&obj->mtx);
	VTAILQ_FOREACH(dir, &obj->active_dirs, list) {
		CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
		Lck_Lock(&dir->mtx);
		AN(dir->thread);
		AZ(pthread_cond_signal(&dir->cond));
		Lck_Unlock(&dir->mtx);
	}

	/* NB: After a call to pthread_join we know for sure that the only
	 * potential contender stopped. Therefore locking is no longer
	 * required to access a (struct dns_director *)->status.
	 */

	VTAILQ_FOREACH(dir, &obj->active_dirs, list) {
		CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
		AZ(pthread_join(dir->thread, NULL));
		assert(dir->status == NAMED_ST_DONE);
		dir->thread = 0;
		dir->status = NAMED_ST_READY;
	}

	VTAILQ_FOREACH_SAFE(dir, &obj->purged_dirs, list, d2) {
		CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
		Lck_Lock(&dir->mtx);
		assert(dir->status == NAMED_ST_STALE ||
		    dir->status == NAMED_ST_DONE);
		Lck_Unlock(&dir->mtx);
		AZ(pthread_join(dir->thread, NULL));
		assert(dir->status == NAMED_ST_DONE);
		dir->status = NAMED_ST_READY;
		vmod_dns_free(NULL, dir);
		VTAILQ_REMOVE(&dir->obj->purged_dirs, dir, list);
	}

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = obj->vcl;
	VRT_rel_vcl(&ctx, &obj->vclref);
	Lck_Unlock(&obj->mtx);
}

static void
vmod_dns_start(struct vmod_named_director *obj)
{
	struct dns_director *dir;
	struct vrt_ctx ctx;

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);
	AZ(obj->vclref);

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = obj->vcl;
	/* XXX: name it "named director %s" instead */
	obj->vclref = VRT_ref_vcl(&ctx, "vmod named");

	Lck_Lock(&obj->mtx);
	VTAILQ_FOREACH(dir, &obj->active_dirs, list) {
		CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
		assert(dir->status == NAMED_ST_READY);
		AZ(dir->thread);
		AZ(pthread_create(&dir->thread, NULL, &vmod_dns_lookup_thread,
		    dir));
	}
	Lck_Unlock(&obj->mtx);
}

static struct dns_director *
vmod_dns_search(VRT_CTX, struct vmod_named_director *obj, const char *addr)
{
	struct dns_director *dir, *d, *d2;

	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);
	AN(addr);

	dir = NULL;
	VTAILQ_FOREACH_SAFE(d, &obj->active_dirs, list, d2) {
		CHECK_OBJ_NOTNULL(d, DNS_DIRECTOR_MAGIC);
		if (!strcmp(d->addr, addr)) {
			AZ(dir);
			dir = d;
		}
		if (dir != d && d->status == NAMED_ST_ACTIVE &&
		    obj->usage_tmo > 0 &&
		    ctx->now - d->last_used > obj->usage_tmo) {
			LOG(ctx, SLT_VCL_Log, d, "%s", "timeout");
			Lck_Lock(&d->mtx);
			d->status = NAMED_ST_STALE;
			AZ(pthread_cond_signal(&d->cond));
			Lck_Unlock(&d->mtx);
			VTAILQ_REMOVE(&d->obj->active_dirs, d, list);
			VTAILQ_INSERT_TAIL(&d->obj->purged_dirs, d, list);
		}
	}

	VTAILQ_FOREACH_SAFE(d, &obj->purged_dirs, list, d2) {
		CHECK_OBJ_NOTNULL(d, DNS_DIRECTOR_MAGIC);
		if (d->status == NAMED_ST_DONE) {
			AZ(pthread_join(d->thread, NULL));
			Lck_Lock(&d->mtx);
			d->thread = 0;
			d->status = NAMED_ST_READY;
			Lck_Unlock(&d->mtx);
			vmod_dns_free(ctx, d);
			VTAILQ_REMOVE(&dir->obj->purged_dirs, d, list);
		}
	}

	return (dir);
}

static struct dns_director *
vmod_dns_get(VRT_CTX, struct vmod_named_director *obj, const char *addr)
{
	struct dns_director *dir;

	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);
	AN(addr);

	dir = vmod_dns_search(ctx, obj, addr);
	if (dir != NULL)
		return (dir);

	ALLOC_OBJ(dir, DNS_DIRECTOR_MAGIC);
	VTAILQ_INIT(&dir->entries);
	REPLACE(dir->addr, addr);
	dir->port = obj->port;
	dir->obj = obj;

	INIT_OBJ(&dir->dir, DIRECTOR_MAGIC);
	dir->dir.name = "dns";
	dir->dir.vcl_name = dir->obj->vcl_name;
	dir->dir.healthy = vmod_dns_healthy;
	dir->dir.resolve = vmod_dns_resolve;
	dir->dir.priv = dir;

	Lck_New(&dir->mtx, lck_be);
	AZ(pthread_cond_init(&dir->cond, NULL));
	AZ(pthread_cond_init(&dir->resolve, NULL));

	AZ(pthread_create(&dir->thread, NULL, &vmod_dns_lookup_thread, dir));

	VTAILQ_INSERT_TAIL(&obj->active_dirs, dir, list);

	return dir;
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
				vmod_dns_start(obj);
			else
				vmod_dns_stop(obj);
		}

	return (0);
}

VCL_VOID __match_proto__()
vmod_director__init(VRT_CTX,
    struct vmod_named_director **objp,
    const char *vcl_name,
    VCL_STRING port,
    VCL_PROBE probe,
    VCL_ACL whitelist,
    VCL_DURATION ttl,
    VCL_DURATION usage_timeout,
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
	VTAILQ_INIT(&obj->active_dirs);
	VTAILQ_INIT(&obj->purged_dirs);
	VTAILQ_INIT(&obj->entries);
	REPLACE(obj->vcl_name, vcl_name);
	REPLACE(obj->port, port);

	obj->vcl_conf = VCL_Name(ctx->vcl);
	obj->vcl = ctx->vcl;
	obj->active = 0;
	obj->probe = probe;
	obj->whitelist = whitelist;
	obj->ttl = ttl;
	obj->usage_tmo = usage_timeout;
	obj->first_tmo = first_lookup_timeout;

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
	while (!VTAILQ_EMPTY(&obj->purged_dirs)) {
		vmod_dns_free(NULL, VTAILQ_FIRST(&obj->purged_dirs));
		VTAILQ_REMOVE(&obj->purged_dirs,
		    VTAILQ_FIRST(&obj->purged_dirs), list);
	}

	while (!VTAILQ_EMPTY(&obj->active_dirs)) {
		vmod_dns_free(NULL, VTAILQ_FIRST(&obj->active_dirs));
		VTAILQ_REMOVE(&obj->active_dirs,
		    VTAILQ_FIRST(&obj->active_dirs), list);
	}

	assert(VTAILQ_EMPTY(&obj->entries));

	Lck_Delete(&obj->mtx);
	free(obj->vcl_name);
	FREE_OBJ(obj);
}

VCL_BACKEND __match_proto__(td_named_director_backend)
vmod_director_backend(VRT_CTX, struct vmod_named_director *obj, VCL_STRING host)
{
	struct dns_director *dir;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(obj, VMOD_NAMED_DIRECTOR_MAGIC);

	if ((host == NULL || *host == '\0') && ctx->http_bereq != NULL)
		host = VRT_GetHdr(ctx, &HDR_BEREQ_HOST);

	if ((host == NULL || *host == '\0') && ctx->http_req != NULL)
		host = VRT_GetHdr(ctx, &HDR_REQ_HOST);

	if (host == NULL || *host == '\0')
		return (NULL);

	Lck_Lock(&obj->mtx);
	dir = vmod_dns_get(ctx, obj, host);
	dir->last_used = ctx->now;
	Lck_Unlock(&obj->mtx);

	return (&dir->dir);
}
