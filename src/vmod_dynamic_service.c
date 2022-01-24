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

#define LOG(ctx, slt, srv, fmt, ...)				\
	do {							\
		if ((ctx)->vsl != NULL)				\
			VSLb((ctx)->vsl, slt,			\
			    "vmod-dynamic: %s %s %s " fmt,	\
			    (srv)->obj->vcl_conf,		\
			    (srv)->obj->vcl_name,		\
			    (srv)->service, __VA_ARGS__);	\
		else						\
			VSL(slt, 0,				\
			    "vmod-dynamic: %s %s %s " fmt,	\
			    (srv)->obj->vcl_conf,		\
			    (srv)->obj->vcl_name,		\
			    (srv)->service, __VA_ARGS__);	\
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

static const struct vdi_methods vmod_dynamic_service_methods[1] = {{
	.magic =	VDI_METHODS_MAGIC,
	.type =		"dynamic service",
	.healthy =	service_healthy,
	.resolve =	service_resolve
}};

/*--------------------------------------------------------------------
 * Service director implementation
 */

/* select healthy backends */
struct backend_select {
	VCL_BACKEND	d;
	uint32_t	w;
};

static VCL_BACKEND v_matchproto_(vdi_resolve_f)
service_resolve(VRT_CTX, VCL_BACKEND d)
{
	struct dynamic_service *srv;
	const struct service_prios *prios;
	const struct service_prio *p;
	const struct service_target *t;
	int ret;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(srv, d->priv, DYNAMIC_SERVICE_MAGIC);

	Lck_Lock(&srv->mtx);

	if (srv->status < DYNAMIC_ST_ACTIVE) {
		ret = Lck_CondWaitTimeout(&srv->resolve, &srv->mtx,
		    srv->obj->first_lookup_tmo);
		assert(ret == 0 || ret == ETIMEDOUT);
	}

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
	VTAILQ_FOREACH(p, &prios->head, list) {
		CHECK_OBJ_NOTNULL(p, SERVICE_PRIO_MAGIC);
		n = w = 0;
		VTAILQ_FOREACH(t, &p->targets, list) {
			CHECK_OBJ_NOTNULL(t, SERVICE_TARGET_MAGIC);
			CHECK_OBJ_NOTNULL(t->dom, DYNAMIC_DOMAIN_MAGIC);
			if (! VRT_Healthy(ctx, t->dom->dir, NULL))
				continue;
			h[n].d = t->dom->dir;
			h[n].w = t->weight;
			w += t->weight;
			n++;
		}
		assert(n <= prios->max_targets);
		if (n > 0)
			break;
	}
	if (n == 0)
		return (NULL);
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
			CHECK_OBJ_NOTNULL(t->dom, DYNAMIC_DOMAIN_MAGIC);
			ret |= VRT_Healthy(ctx, t->dom->dir, &c);
			if (changed != NULL && c > *changed)
				*changed = c;
		}
	}

	return (ret);
}

/*--------------------------------------------------------------------
 * Background job
 */

/* add all the dom objects an ensure they are active */

static void
service_doms(VRT_CTX, struct vmod_dynamic_director *obj,
    struct service_prios *prios)
{
	struct dynamic_domain *dom;
	struct service_prio *p;
	struct service_target *t;
	char portbuf[6];
	unsigned n;
	int ret;

	CHECK_OBJ_NOTNULL(prios, SERVICE_PRIOS_MAGIC);

	Lck_Lock(&obj->mtx);
	VTAILQ_FOREACH(p, &prios->head, list) {
		CHECK_OBJ_NOTNULL(p, SERVICE_PRIO_MAGIC);
		n = 0;
		VTAILQ_FOREACH(t, &p->targets, list) {
			CHECK_OBJ_NOTNULL(t, SERVICE_TARGET_MAGIC);
			bprintf(portbuf, "%u", t->port);
			t->dom = dynamic_get(ctx, obj, t->target, portbuf);
			AN(t->dom);
			t->dom->last_used = ctx->now;
			n++;
		}
		p->n_targets = n;
		if (n > prios->max_targets)
			prios->max_targets = n;
	}
	Lck_Unlock(&obj->mtx);

	VTAILQ_FOREACH(p, &prios->head, list) {
		CHECK_OBJ_NOTNULL(p, SERVICE_PRIO_MAGIC);
		VTAILQ_FOREACH(t, &p->targets, list) {
			CHECK_OBJ_NOTNULL(t, SERVICE_TARGET_MAGIC);
			dom = t->dom;
			CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
			if (dom->status >= DYNAMIC_ST_ACTIVE)
				continue;
			Lck_Lock(&dom->mtx);
			while (dom->status < DYNAMIC_ST_ACTIVE) {
				ret = Lck_CondWaitTimeout(&dom->resolve,
				    &dom->mtx,
				    dom->obj->first_lookup_tmo);
				assert(ret == 0 || ret == ETIMEDOUT);
			}
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

	VSL(SLT_Timestamp, 0, "vmod-dynamic %s.%s(srv %s) %s: %.6f %.6f %.6f",
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

	while (obj->active && srv->status <= DYNAMIC_ST_ACTIVE) {

		lookup = VTIM_real();
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

		if (srv->status == DYNAMIC_ST_READY) {
			AZ(pthread_cond_broadcast(&srv->resolve));
			srv->status = DYNAMIC_ST_ACTIVE;
		}

		/* Check status again after the blocking call */
		if (obj->active && srv->status <= DYNAMIC_ST_ACTIVE) {
			ret = Lck_CondWaitUntil(&srv->cond, &srv->mtx,
			    srv->deadline);
			assert(ret == 0 || ret == ETIMEDOUT);
		}

		Lck_Unlock(&srv->mtx);
	}

	srv->status = DYNAMIC_ST_DONE;
	service_timestamp(srv, "Done", VTIM_real(), 0., 0.);

	return (NULL);
}

static void
service_free(VRT_CTX, struct dynamic_service *srv)
{
	CHECK_OBJ_ORNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(srv, DYNAMIC_SERVICE_MAGIC);
	AZ(srv->thread);
	assert(srv->status == DYNAMIC_ST_READY);

	VRT_DelDirector(&srv->dir);

	if (ctx != NULL) {
		Lck_AssertHeld(&srv->obj->mtx);
		LOG(ctx, SLT_VCL_Log, srv, "%s", "deleted");
	}

	if (srv->prios_cold != NULL)
		service_prios_free(&srv->prios_cold);
	if (srv->prios != NULL)
		service_prios_free(&srv->prios);
	AZ(srv->prios_cold);
	AZ(srv->prios);

	AZ(pthread_cond_destroy(&srv->resolve));
	AZ(pthread_cond_destroy(&srv->cond));
	Lck_Delete(&srv->mtx);
	REPLACE(srv->service, NULL);
	FREE_OBJ(srv);
}

static void
service_join(struct dynamic_service *srv)
{
	CHECK_OBJ_NOTNULL(srv, DYNAMIC_SERVICE_MAGIC);
	AN(srv->thread);
	AZ(pthread_join(srv->thread, NULL));
	assert(srv->status == DYNAMIC_ST_DONE);
	srv->thread = 0;
	srv->status = DYNAMIC_ST_READY;
}

// called from dynamic_stop
void
service_stop(struct vmod_dynamic_director *obj)
{
	struct dynamic_service *srv, *s2;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	VTAILQ_FOREACH(srv, &obj->active_services, list) {
		CHECK_OBJ_NOTNULL(srv, DYNAMIC_SERVICE_MAGIC);
		Lck_Lock(&srv->mtx);
		AN(srv->thread);
		AZ(pthread_cond_signal(&srv->cond));
		Lck_Unlock(&srv->mtx);
	}
	VTAILQ_FOREACH(srv, &obj->active_services, list)
		service_join(srv);

	VTAILQ_FOREACH_SAFE(srv, &obj->purged_services, list, s2) {
		CHECK_OBJ_NOTNULL(srv, DYNAMIC_SERVICE_MAGIC);
		assert(srv->status == DYNAMIC_ST_STALE ||
		    srv->status == DYNAMIC_ST_DONE);
		service_join(srv);
		VTAILQ_REMOVE(&obj->purged_services, srv, list);
		service_free(NULL, srv);
	}
}

// called from dynamic_start
void
service_start(VRT_CTX, struct vmod_dynamic_director *obj)
{
	struct dynamic_service *srv;

	(void) ctx;
	Lck_AssertHeld(&obj->mtx);

	VTAILQ_FOREACH(srv, &obj->active_services, list) {
		CHECK_OBJ_NOTNULL(srv, DYNAMIC_SERVICE_MAGIC);
		assert(srv->status == DYNAMIC_ST_READY);
		AZ(srv->thread);
		AZ(pthread_create(&srv->thread, NULL, service_lookup_thread,
		    srv));
	}
}

// calledn from vmod_director__fini
void
service_fini(struct vmod_dynamic_director *obj)
{
	struct dynamic_service *srv, *s2;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	VTAILQ_FOREACH_SAFE(srv, &obj->purged_services, list, s2) {
		VTAILQ_REMOVE(&obj->purged_services, srv, list);
		service_free(NULL, srv);
	}

	VTAILQ_FOREACH_SAFE(srv, &obj->active_services, list, s2) {
		VTAILQ_REMOVE(&obj->active_services, srv, list);
		service_free(NULL, srv);
	}

}

static struct dynamic_service *
service_search(VRT_CTX, struct vmod_dynamic_director *obj, const char *service)
{
	struct dynamic_service *srv, *s, *s2;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);
	AN(service);

	srv = NULL;
	VTAILQ_FOREACH_SAFE(s, &obj->active_services, list, s2) {
		CHECK_OBJ_NOTNULL(s, DYNAMIC_SERVICE_MAGIC);
		if (strcmp(s->service, service) == 0)
			srv = s;
		if (srv != s && s->status == DYNAMIC_ST_ACTIVE &&
		    obj->domain_usage_tmo > 0 &&
		    ctx->now - s->last_used > obj->domain_usage_tmo) {
			LOG(ctx, SLT_VCL_Log, s, "%s", "timeout");
			Lck_Lock(&s->mtx);
			s->status = DYNAMIC_ST_STALE;
			AZ(pthread_cond_signal(&s->cond));
			Lck_Unlock(&s->mtx);
			VTAILQ_REMOVE(&obj->active_services, s, list);
			VTAILQ_INSERT_TAIL(&obj->purged_services, s, list);
		}
	}

	VTAILQ_FOREACH_SAFE(s, &obj->purged_services, list, s2) {
		CHECK_OBJ_NOTNULL(s, DYNAMIC_SERVICE_MAGIC);
		if (s->status == DYNAMIC_ST_DONE) {
			service_join(s);
			VTAILQ_REMOVE(&obj->purged_services, s, list);
			service_free(ctx, s);
		}
	}

	return (srv);
}

static struct dynamic_service *
service_get(VRT_CTX, struct vmod_dynamic_director *obj, const char *service)
{
	struct dynamic_service *srv;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);
	AN(service);

	srv = service_search(ctx, obj, service);
	if (srv != NULL)
		return (srv);

	ALLOC_OBJ(srv, DYNAMIC_SERVICE_MAGIC);
	AN(srv);

	REPLACE(srv->service, service);

	srv->obj = obj;

	srv->dir = VRT_AddDirector(ctx, vmod_dynamic_service_methods, srv,
	    "%s(%s)", obj->vcl_name, service);

	Lck_New(&srv->mtx, lck_be);
	AZ(pthread_cond_init(&srv->cond, NULL));
	AZ(pthread_cond_init(&srv->resolve, NULL));

	AZ(pthread_create(&srv->thread, NULL, service_lookup_thread, srv));

	VTAILQ_INSERT_TAIL(&obj->active_services, srv, list);

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

	Lck_Lock(&obj->mtx);
	srv = service_get(ctx, obj, service);
	AN(srv);
	srv->last_used = ctx->now;
	Lck_Unlock(&obj->mtx);

	return (srv->dir);
}
