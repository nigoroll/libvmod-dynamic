/*-
 * Copyright (c) 2015-2016 Varnish Software AS
 * Copyright 2017-2019 UPLEX - Nils Goroll Systemoptimierung
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
 *
 * Support for SRV records.
 *
 * For now, this code is basically a copy of large extents of vmod_dynamic.c as
 * a first iteration. Consolidation is left for later.
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
#include <string.h>

#include <cache/cache.h>

#include <vtim.h>
#include <vrnd.h>

#include "vcc_dynamic_if.h"
#include "dyn_resolver.h"
#include "vmod_dynamic.h"
#include "vmb.h"

#define LOG(ctx, slt, srv, fmt, ...)					\
	do {								\
		dylog(ctx, slt,					\
		    "vmod-dynamic %s %s %s " fmt,			\
		    (srv)->obj->vcl_conf,				\
		    (srv)->obj->vcl_name,				\
		    (srv)->service, __VA_ARGS__);			\
	} while (0)

#define DBG(ctx, srv, fmt, ...)						\
	do {								\
		if ((srv)->obj->debug)					\
			LOG(ctx, SLT_Debug, srv, fmt, __VA_ARGS__);	\
	} while (0)

static VCL_BACKEND v_matchproto_(vdi_resolve_f)
service_resolve(VRT_CTX, VCL_BACKEND);
static VCL_BOOL v_matchproto_(vdi_healthy_f)
service_healthy(VRT_CTX, VCL_BACKEND, VCL_TIME *);
static void v_matchproto_(vdi_release_f)
service_release(VCL_BACKEND dir);
static void v_matchproto_(vdi_destroy_f)
service_destroy(VCL_BACKEND dir);

static const struct vdi_methods vmod_dynamic_service_methods[1] = {{
	.magic =	VDI_METHODS_MAGIC,
	.type =		"dynamic service",
	.healthy =	service_healthy,
	.resolve =	service_resolve,
	.destroy =	service_destroy
}};

/*--------------------------------------------------------------------
 * active services tree
 */

static inline int
dynamic_service_cmp(const struct dynamic_service *a,
    const struct dynamic_service *b)
{
	CHECK_OBJ_NOTNULL(a, DYNAMIC_SERVICE_MAGIC);
	CHECK_OBJ_NOTNULL(b, DYNAMIC_SERVICE_MAGIC);

	return (strcmp(a->service, b->service));
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

VRBT_GENERATE_NEEDED(srv_tree_head, dynamic_service,
    link.tree, dynamic_service_cmp, static)

/*--------------------------------------------------------------------
 * Service director implementation
 */

/* select healthy backends */
struct backend_select {
	VCL_BACKEND	d;
	uint32_t	w;
};

static void
service_wait_active(struct dynamic_service *srv)
{
	int ret;

	CHECK_OBJ_NOTNULL(srv, DYNAMIC_SERVICE_MAGIC);

	if (srv->status >= DYNAMIC_ST_ACTIVE)
		return;

	DBG(NULL, srv, "%s", "wait-active");

	ret = Lck_CondWaitTimeout(&srv->resolve, &srv->mtx,
	    srv->obj->first_lookup_tmo);
	assert(ret == 0 || ret == ETIMEDOUT);
	DBG(NULL, srv, "wait-active ret %d", ret);
}

static VCL_BACKEND v_matchproto_(vdi_resolve_f)
service_resolve(VRT_CTX, VCL_BACKEND d)
{
	struct dynamic_service *srv;
	const struct service_prios *prios;
	const struct service_prio *p;
	const struct service_target *t;
	VCL_BACKEND dir;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(srv, d->priv, DYNAMIC_SERVICE_MAGIC);

	Lck_Lock(&srv->mtx);

	service_wait_active(srv);

	if (srv->status > DYNAMIC_ST_ACTIVE) {
		Lck_Unlock(&srv->mtx);
		return (NULL);
	}
	Lck_Unlock(&srv->mtx);

	VRMB();
	prios = srv->prios;

	if (prios == NULL)
		return (NULL);

	struct backend_select	h[prios->max_targets];
	unsigned i, n, w;
	long r;

	memset(h, 0, sizeof h);

	n = w = 0;
	dir = NULL;
	VTAILQ_FOREACH(p, &prios->head, list) {
		CHECK_OBJ_NOTNULL(p, SERVICE_PRIO_MAGIC);
		n = w = 0;
		VTAILQ_FOREACH(t, &p->targets, list) {
			CHECK_OBJ_NOTNULL(t, SERVICE_TARGET_MAGIC);
			dir = t->dir;
			if (! VRT_Healthy(ctx, t->dir, NULL))
				continue;
			h[n].d = t->dir;
			h[n].w = t->weight;
			w += t->weight;
			n++;
		}
		assert(n <= prios->max_targets);
		if (n > 0)
			break;
	}
	if (n == 0)
		return (dir);
	if (n == 1)
		return (h[0].d);
	// fixup zero weight
	if (w == 0) {
		for (i = 0; i < n; i++)
			h[i].w = 1;
		w = n;
	}
	r = VRND_RandomTestable() % w;
	w = 0;
	for (i = 0; i < n; i++) {
		w += h[i].w;
		if (r < w)
			return (h[i].d);
	}
	WRONG("");
}

static VCL_BOOL v_matchproto_(vdi_healthy_f)
service_healthy(VRT_CTX, VCL_BACKEND d, VCL_TIME *changed)
{
	struct dynamic_service *srv;
	const struct service_prios *prios;
	const struct service_prio *p;
	const struct service_target *t;
	VCL_TIME c;
	VCL_BOOL ret = 0;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(srv, d->priv, DYNAMIC_SERVICE_MAGIC);

	Lck_Lock(&srv->mtx);
	service_wait_active(srv);
	Lck_Unlock(&srv->mtx);

	VRMB();
	prios = srv->prios;

	if (prios == NULL)
		return (0);

	if (changed != NULL)
		*changed = 0;

	VTAILQ_FOREACH(p, &prios->head, list) {
		CHECK_OBJ_NOTNULL(p, SERVICE_PRIO_MAGIC);
		VTAILQ_FOREACH(t, &p->targets, list) {
			CHECK_OBJ_NOTNULL(t, SERVICE_TARGET_MAGIC);
			ret |= VRT_Healthy(ctx, t->dir, &c);
			if (changed != NULL && c > *changed)
				*changed = c;
		}
	}

	return (ret);
}

/*--------------------------------------------------------------------
 * Background job
 */

/* add all the dom objects and ensure they are active */

static void
service_doms(VRT_CTX, struct vmod_dynamic_director *obj,
    struct service_prios *prios)
{
	struct dynamic_domain *dom;
	struct service_prio *p;
	struct service_target *t;
	char portbuf[6];
	unsigned n;

	CHECK_OBJ_NOTNULL(prios, SERVICE_PRIOS_MAGIC);

	VTAILQ_FOREACH(p, &prios->head, list) {
		CHECK_OBJ_NOTNULL(p, SERVICE_PRIO_MAGIC);
		n = 0;
		VTAILQ_FOREACH(t, &p->targets, list) {
			CHECK_OBJ_NOTNULL(t, SERVICE_TARGET_MAGIC);
			bprintf(portbuf, "%u", t->port);
			dom = dynamic_get(ctx, obj, t->target, NULL, portbuf);
			AN(dom);
			VRT_Assign_Backend(&t->dir, dom->dir);
			CHECK_OBJ_NOTNULL(t->dir, DIRECTOR_MAGIC);
			n++;
		}
		p->n_targets = n;
		if (n > prios->max_targets)
			prios->max_targets = n;
	}

	VTAILQ_FOREACH(p, &prios->head, list) {
		CHECK_OBJ_NOTNULL(p, SERVICE_PRIO_MAGIC);
		VTAILQ_FOREACH(t, &p->targets, list) {
			CHECK_OBJ_NOTNULL(t, SERVICE_TARGET_MAGIC);
			CHECK_OBJ_NOTNULL(t->dir, DIRECTOR_MAGIC);
			CAST_OBJ_NOTNULL(dom, t->dir->priv,
			    DYNAMIC_DOMAIN_MAGIC);
			if (dom->status >= DYNAMIC_ST_ACTIVE)
				continue;
			Lck_Lock(&dom->mtx);
			dom_wait_active(dom);
			Lck_Unlock(&dom->mtx);
		}
	}
}

static void
service_prios_free(struct service_prios **priosp)
{
	struct service_prios *prios = *priosp;
	struct service_prio *p, *pt;
	struct service_target *t, *tt;

	TAKE_OBJ_NOTNULL(prios, priosp, SERVICE_PRIOS_MAGIC);
	VTAILQ_FOREACH_SAFE(p, &prios->head, list, pt) {
		CHECK_OBJ_NOTNULL(p, SERVICE_PRIO_MAGIC);
		VTAILQ_FOREACH_SAFE(t, &p->targets, list, tt) {
			CHECK_OBJ_NOTNULL(t, SERVICE_TARGET_MAGIC);
			VRT_Assign_Backend(&t->dir, NULL);
			AZ(t->dir);
			AN(t->target);
			free(t->target);
			FREE_OBJ(t);
		}
		FREE_OBJ(p);
	}
	FREE_OBJ(prios);
}

static struct service_prio *
service_prio(struct service_prios *prios, uint32_t priority)
{
	struct service_prio *p, *prio;

	VTAILQ_FOREACH(p, &prios->head, list) {
		if (p->priority == priority)
			return (p);
		if (p->priority > priority)
			break;
	}

	ALLOC_OBJ(prio, SERVICE_PRIO_MAGIC);
	AN(prio);
	prio->priority = priority;
	VTAILQ_INIT(&prio->targets);

	if (p)
		VTAILQ_INSERT_BEFORE(p, prio, list);
	else
		VTAILQ_INSERT_TAIL(&prios->head, prio, list);

	return (prio);
}

/* we order targets for deterministic testing by target and port.
 * being at it, we also just add the weight for identical target:port
 */

static int
target_cmp(const struct service_target *t, const struct srv_info *i)
{
	int ret;

	CHECK_OBJ_NOTNULL(t, SERVICE_TARGET_MAGIC);
	AN(i);

	ret = strcmp(t->target, i->target);
	if (ret != 0)
		return (ret);
	if (t->port == i->port)
		return (0);
	return (t->port < i->port ? -1 : 1);
}

static struct service_target *
service_target(struct service_prio *prio, const struct srv_info *i)
{
	struct service_target *t, *target;
	int cmp;

	VTAILQ_FOREACH(t, &prio->targets, list) {
		cmp = target_cmp(t, i);
		if (cmp == 0)
			return (t);
		if (cmp > 0)
			break;
	}

	ALLOC_OBJ(target, SERVICE_TARGET_MAGIC);
	AN(target);

	if (t)
		VTAILQ_INSERT_BEFORE(t, target, list);
	else
		VTAILQ_INSERT_TAIL(&prio->targets, target, list);

	return (target);
}

static void
service_update(struct dynamic_service *srv, const struct res_cb *res,
    void **res_privp, vtim_real now)
{
	struct vrt_ctx ctx;
	struct srv_info ibuf[1] = {{ 0 }};
	struct srv_info *info;
	void *state = NULL;
	vtim_dur ttl = NAN;
	struct service_prios *prios;
	struct service_prio *prio = NULL;
	struct service_target *target;
	void *res_priv;

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = srv->obj->vcl;
	ctx.now = now;

	AN(res_privp);
	res_priv = *res_privp;
	AN(res_priv);
	*res_privp = NULL;

	/*
	 * we free any cold prio/target tree, create a new one, then swap
	 * the single head pointer after a membar
	 *
	 * director resolve races us
	 */

	ALLOC_OBJ(prios, SERVICE_PRIOS_MAGIC);
	AN(prios);
	VTAILQ_INIT(&prios->head);
	while ((info = res->srv_result(ibuf, res_priv, &state)) != NULL) {
		DBG(&ctx, srv, "DNS SRV %s:%d priority %d weight %d ttl %d",
		    info->target, info->port, info->priority,
		    info->weight, info->ttl);

		if (prio != NULL && prio->priority != info->priority)
			prio = NULL;
		if (prio == NULL)
			prio = service_prio(prios, info->priority);

		target = service_target(prio, info);

		if (target->target != NULL) {
			// existing
			assert(target->port == info->port);
			target->weight += info->weight;
			free(info->target);
			info->target = NULL;
		} else {
			target->port = info->port;
			target->weight = info->weight;
			// target is malloc'ed - take it
			target->target = info->target;
			info->target = NULL;
		}

		if (info->ttl != 0 && (isnan(ttl) || info->ttl < ttl))
			ttl = info->ttl;

		DBG(&ctx, srv, "target %s:%d priority %d weight %d ttl %f",
		    target->target, target->port, prio->priority,
		    target->weight, ttl);
	}

	res->srv_fini(&res_priv);
	AZ(res_priv);

	service_doms(&ctx, srv->obj, prios);

	if (srv->prios_cold != NULL)
		service_prios_free(&srv->prios_cold);

	VWMB();
	AZ(srv->prios_cold);
	srv->prios_cold = srv->prios;
	srv->prios = prios;

	if (isnan(ttl)) {
		ttl = srv->obj->ttl;
	} else if (srv->obj->ttl_from == cfg) {
		ttl = srv->obj->ttl;
	} else if (srv->obj->ttl_from == min) {
		if (srv->obj->ttl < ttl)
			ttl = srv->obj->ttl;
	} else if (srv->obj->ttl_from == max) {
		if (srv->obj->ttl > ttl)
			ttl = srv->obj->ttl;
	} else {
		assert(srv->obj->ttl_from == dns);
	}
	srv->deadline = now + ttl;

	DBG(&ctx, srv, "deadline %f ttl %f", srv->deadline, ttl);
}

static void
service_timestamp(struct dynamic_service *srv, const char *event, double start,
    double dfirst, double dprev)
{

	VSL(SLT_Timestamp, NO_VXID,
	    "vmod-dynamic %s.%s(srv %s) %s: %.6f %.6f %.6f",
	    srv->obj->vcl_conf, srv->obj->vcl_name, srv->service,
	    event, start, dfirst, dprev);
}

static void*
service_lookup_thread(void *priv)
{
	struct vmod_dynamic_director *obj;
	struct dynamic_service *srv;
	struct vrt_ctx ctx;
	vtim_real lookup, results, update;
	const struct res_cb *res;
	void *res_priv = NULL;
	int ret;

	CAST_OBJ_NOTNULL(srv, priv, DYNAMIC_SERVICE_MAGIC);
	INIT_OBJ(&ctx, VRT_CTX_MAGIC);

	obj = srv->obj;
	res = obj->resolver;

	AN(res->srv_lookup);
	AN(res->srv_result);
	AN(res->srv_fini);

	assert(srv->status == DYNAMIC_ST_STARTING);

	while (obj->active && srv->status <= DYNAMIC_ST_ACTIVE) {

		lookup = VTIM_real();
		if (lookup > srv->expires) {
			LOG(NULL, SLT_VCL_Log, srv, "%s", "timeout");
			srv->status = DYNAMIC_ST_STALE;
			break;
		}

		service_timestamp(srv, "Lookup", lookup, 0., 0.);

		ret = res->srv_lookup(obj->resolver_inst, srv->service,
		    &res_priv);

		results = VTIM_real();
		service_timestamp(srv, "Results", results, results - lookup,
		    results - lookup);

		if (ret == 0) {
			service_update(srv, res, &res_priv, results);
			update = VTIM_real();
			service_timestamp(srv, "Update", update,
			    update - lookup, update - results);
			// minimum update delay for lockless safety
			update += 0.01;
			if (srv->deadline < update)
				srv->deadline = update;
			// maximum update delay
			if (obj->domain_usage_tmo > 0) {
				update += obj->domain_usage_tmo / 2;
				if (srv->deadline > update)
					srv->deadline = update;
			}
		} else {
			LOG(&ctx, SLT_Error, srv, "%s %d (%s)",
			    res->name, ret, res->strerror(ret));
			srv->deadline = results + obj->retry_after;
			dbg_res_details(NULL, srv->obj, res, res_priv);
			res->srv_fini(&res_priv);
		}

		AZ(res_priv);

		Lck_Lock(&srv->mtx);

		if (srv->status == DYNAMIC_ST_STARTING) {
			AZ(pthread_cond_broadcast(&srv->resolve));
			srv->status = DYNAMIC_ST_ACTIVE;
		}

		/* Check status again after the blocking call */
		if (obj->active && srv->status <= DYNAMIC_ST_ACTIVE) {
			ret = Lck_CondWaitUntil(&srv->cond, &srv->mtx,
			    fmin(srv->deadline, srv->expires));
			assert(ret == 0 || ret == ETIMEDOUT);
		}

		Lck_Unlock(&srv->mtx);
	}

	if (srv->status == DYNAMIC_ST_STALE) {
		Lck_Lock(&obj->services_mtx);
		VRBT_REMOVE(srv_tree_head, &obj->ref_services, srv);
		VTAILQ_INSERT_TAIL(&obj->unref_services, srv, link.list);
		Lck_Unlock(&obj->services_mtx);
	}
	else
		srv->status = DYNAMIC_ST_DONE;

	service_timestamp(srv, "Done", VTIM_real(), 0., 0.);

	return (NULL);
}

static void v_matchproto_(vdi_release_f)
service_release(VCL_BACKEND dir)
{
	struct dynamic_service *srv;

	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(srv, dir->priv, DYNAMIC_SERVICE_MAGIC);

	AZ(srv->thread);
	assert(srv->status == DYNAMIC_ST_READY);

	if (srv->prios_cold != NULL)
		service_prios_free(&srv->prios_cold);
	if (srv->prios != NULL)
		service_prios_free(&srv->prios);
}

static void v_matchproto_(vdi_destroy_f)
service_destroy(VCL_BACKEND dir)
{
	struct dynamic_service *srv;

	service_release(dir);

	CAST_OBJ_NOTNULL(srv, dir->priv, DYNAMIC_SERVICE_MAGIC);
	AZ(srv->thread);
	assert(srv->status == DYNAMIC_ST_READY);
	AZ(srv->prios_cold);
	AZ(srv->prios);

	AZ(pthread_cond_destroy(&srv->resolve));
	AZ(pthread_cond_destroy(&srv->cond));
	Lck_Delete(&srv->mtx);
	REPLACE(srv->service, NULL);
	FREE_OBJ(srv);
}

static void
service_free(struct dynamic_service **srvp, const char *why)
{
	struct dynamic_service *srv;

	TAKE_OBJ_NOTNULL(srv, srvp, DYNAMIC_SERVICE_MAGIC);

	AZ(srv->thread);
	LOG(NULL, SLT_VCL_Log, srv, "deleted (%s)", why);

	VRT_DelDirector(&srv->dir);
}

static enum dynamic_status_e
service_join(struct dynamic_service *srv)
{
	enum dynamic_status_e status;

	CHECK_OBJ_NOTNULL(srv, DYNAMIC_SERVICE_MAGIC);
	AN(srv->thread);
	AZ(pthread_join(srv->thread, NULL));
	status = srv->status;
	assert(status == DYNAMIC_ST_DONE || status == DYNAMIC_ST_STALE);
	srv->thread = 0;
	srv->status = DYNAMIC_ST_READY;
	return (status);
}

static void
service_gc_purged(struct vmod_dynamic_director *obj)
{
	struct dynamic_service *srv;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->services_mtx);

	while ((srv = VTAILQ_FIRST(&obj->unref_services)) != NULL) {
		CHECK_OBJ_NOTNULL(srv, DYNAMIC_DOMAIN_MAGIC);
		assert(srv->status == DYNAMIC_ST_STALE);
		VTAILQ_REMOVE(&obj->unref_services, srv, link.list);
		Lck_Unlock(&obj->services_mtx);
		(void) service_join(srv);
		service_free(&srv, "expired");
		Lck_Lock(&obj->services_mtx);
	}
}

// called from dynamic_stop
void
service_stop(struct vmod_dynamic_director *obj)
{
	struct dynamic_service *srv;
	struct srv_tree_head active_done;
	enum dynamic_status_e status;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	VRBT_INIT(&active_done);

	Lck_Lock(&obj->services_mtx);
	AZ(obj->active);
	// wake up all threads
	VRBT_FOREACH(srv, srv_tree_head, &obj->ref_services) {
		CHECK_OBJ_NOTNULL(srv, DYNAMIC_SERVICE_MAGIC);
		Lck_Lock(&srv->mtx);
		AN(srv->thread);
		AZ(pthread_cond_signal(&srv->cond));
		Lck_Unlock(&srv->mtx);
	}

	while (! (VTAILQ_EMPTY(&obj->unref_services) &&
		  VRBT_EMPTY(&obj->ref_services))) {
		// finished threads can be picked up already
		service_gc_purged(obj);

		while ((srv = VRBT_ROOT(&obj->ref_services)) != NULL) {
			CHECK_OBJ(srv, DYNAMIC_SERVICE_MAGIC);
			Lck_Unlock(&obj->services_mtx);
			status = service_join(srv);
			assert(srv->status == DYNAMIC_ST_READY);
			Lck_Lock(&obj->services_mtx);
			AZ(srv->thread);
			switch (status) {
			case DYNAMIC_ST_STALE:
				VTAILQ_REMOVE(&obj->unref_services, srv, link.list);
				service_free(&srv, "stop expired");
				break;
			case DYNAMIC_ST_DONE:
				VRBT_REMOVE(srv_tree_head, &obj->ref_services, srv);
				AZ(VRBT_INSERT(srv_tree_head, &active_done, srv));
				break;
			default:
				WRONG("status in service_stop");
			}
		}
	}
	assert(VRBT_EMPTY(&obj->ref_services));
	obj->ref_services = active_done;
	Lck_Unlock(&obj->services_mtx);
}

static void
service_start_service(struct dynamic_service *srv)
{

	CHECK_OBJ_NOTNULL(srv, DYNAMIC_SERVICE_MAGIC);
	if (srv->status >= DYNAMIC_ST_STARTING)
		return;
	assert(srv->status == DYNAMIC_ST_READY);
	srv->status = DYNAMIC_ST_STARTING;
	AZ(srv->thread);
	AZ(pthread_create(&srv->thread, NULL, service_lookup_thread, srv));
}

// called from dynamic_start
void
service_start(VRT_CTX, struct vmod_dynamic_director *obj)
{
	struct dynamic_service *srv;

	(void) ctx;
	Lck_Lock(&obj->services_mtx);
	VRBT_FOREACH(srv, srv_tree_head, &obj->ref_services)
	    service_start_service(srv);
	Lck_Unlock(&obj->services_mtx);
}

// calledn from vmod_director__fini
void
service_fini(struct vmod_dynamic_director *obj)
{
	struct dynamic_service *srv;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	assert(VTAILQ_EMPTY(&obj->unref_services));

	while ((srv = VRBT_ROOT(&obj->ref_services)) != NULL) {
		VRBT_REMOVE(srv_tree_head, &obj->ref_services, srv);
		service_free(&srv, "fini");
	}

}

static struct dynamic_service *
service_search(struct vmod_dynamic_director *obj, const char *service)
{
	struct dynamic_service srv[1];

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->services_mtx);
	AN(service);

	if (VTAILQ_FIRST(&obj->unref_services))
		service_gc_purged(obj);

	INIT_OBJ(srv, DYNAMIC_SERVICE_MAGIC);
	srv->service = TRUST_ME(service);	// XXX
	return (VRBT_FIND(srv_tree_head, &obj->ref_services, srv));
}

static struct dynamic_service *
service_get(VRT_CTX, struct vmod_dynamic_director *obj, const char *service)
{
	struct dynamic_service *srv, *raced;
	VCL_TIME t;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	AN(service);

	t = ctx->now + obj->domain_usage_tmo;

	Lck_Lock(&obj->services_mtx);
	srv = service_search(obj, service);
	if (srv != NULL) {
		if (t > srv->expires)
			srv->expires = t;
		Lck_Unlock(&obj->services_mtx);
		return (srv);
	}

	Lck_Unlock(&obj->services_mtx);

	ALLOC_OBJ(srv, DYNAMIC_SERVICE_MAGIC);
	AN(srv);

	REPLACE(srv->service, service);

	srv->obj = obj;
	srv->expires = t;

	srv->dir = VRT_AddDirector(ctx, vmod_dynamic_service_methods, srv,
	    "%s(%s)", obj->vcl_name, service);

	Lck_New(&srv->mtx, lck_be);
	AZ(pthread_cond_init(&srv->cond, NULL));
	AZ(pthread_cond_init(&srv->resolve, NULL));

	Lck_Lock(&obj->services_mtx);
	raced = VRBT_INSERT(srv_tree_head, &obj->ref_services, srv);
	Lck_Unlock(&obj->services_mtx);

	if (raced) {
		service_free(&srv, "raced");
		return (raced);
	}

	obj->active = 1;
	service_start_service(srv);

	return (srv);
}


VCL_BACKEND v_matchproto_(td_dynamic_director_service)
vmod_director_service(VRT_CTX, struct VPFX(dynamic_director) *obj,
    VCL_STRING service) {
	struct dynamic_service *srv;
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	if (obj->resolver_inst == NULL) {
		VRT_fail(ctx, "xdynamic.service(): Only supported "
		    "with a resolver");
		return (NULL);
	}

	srv = service_get(ctx, obj, service);
	AN(srv);

	return (srv->dir);
}
