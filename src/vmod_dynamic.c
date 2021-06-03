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
#include <cache/cache_backend.h>

#include <vsb.h>
#include <vcl.h>
#include <vsa.h>
#include <vtim.h>
#include <vtcp.h>
#include <vrnd.h>

#include "vcc_dynamic_if.h"
#include "dyn_resolver.h"
#include "vmod_dynamic.h"

#define LOG(ctx, slt, dom, fmt, ...)				\
	do {							\
		if ((ctx)->vsl != NULL)				\
			VSLb((ctx)->vsl, slt,			\
			    "vmod-dynamic: %s %s %s:%s " fmt,	\
			    (dom)->obj->vcl_conf,		\
			    (dom)->obj->vcl_name, (dom)->addr,	\
			    dom_port(dom), __VA_ARGS__);		\
		else						\
			VSL(slt, 0,				\
			    "vmod-dynamic: %s %s %s:%s " fmt,	\
			    (dom)->obj->vcl_conf,		\
			    (dom)->obj->vcl_name, (dom)->addr,	\
			    dom_port(dom), __VA_ARGS__);		\
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

static VCL_BACKEND v_matchproto_(vdi_resolve_f)
dynamic_resolve(VRT_CTX, VCL_BACKEND);
static VCL_BOOL v_matchproto_(vdi_healthy_f)
dynamic_healthy(VRT_CTX, VCL_BACKEND, VCL_TIME *);

static const struct vdi_methods vmod_dynamic_methods[1] = {{
	.magic =	VDI_METHODS_MAGIC,
	.type =		"dynamic",
	.healthy =	dynamic_healthy,
	.resolve =	dynamic_resolve
}};

/*--------------------------------------------------------------------
 * Director implementation
 */

static const struct director * v_matchproto_(vdi_resolve_f)
dynamic_resolve_rr(VRT_CTX, struct dynamic_domain *dom)
{
	struct dynamic_ref *next;
	VCL_BACKEND dir;

	if (dom->current == NULL)
		dom->current = VTAILQ_FIRST(&dom->refs);

	next = dom->current;

	do {
		if (next != NULL)
			next = VTAILQ_NEXT(next, list);
		if (next == NULL)
			next = VTAILQ_FIRST(&dom->refs);
	} while (next != dom->current &&
		 !VRT_Healthy(ctx, next->be->dir, NULL));

	dom->current = next;

	if (next == NULL)
		return (NULL);

	dir = next->be->dir;

	if (!VRT_Healthy(ctx, dir, NULL))
		return (NULL);

	return (dir);
}

/** Returns the number of connections available for the given domain and backend ref. */
static unsigned dynamic_connections_available(struct dynamic_domain *dom, struct dynamic_ref *r, unsigned max_connections)
{
	struct backend *be;
	unsigned n_conn;

	CAST_OBJ_NOTNULL(be, r->be->dir->priv, BACKEND_MAGIC);
	n_conn = be->n_conn;

	if (n_conn >= max_connections) {
		/* Already at max_connections, so indicate no available connections */
		return 0;
	} else if (n_conn < dom->obj->slow_start_max_connections) {
		/* Below the slow start number of connections */
		double p;
		unsigned simulated_connections_available;

		p = dom->obj->slow_start_percentage + (1.0 - dom->obj->slow_start_percentage) * ((double)n_conn / dom->obj->slow_start_max_connections);
		simulated_connections_available = (max_connections - n_conn) * p;

		if (simulated_connections_available < 1) {
			simulated_connections_available = 1;
		}
		return simulated_connections_available;
	} else {
		return max_connections - n_conn;
	}
}

/** Return the effective number of max_connections to use in our least connections algorithm. */
static unsigned dynamic_effective_max_connections(VRT_CTX, struct dynamic_domain *dom)
{
	struct dynamic_ref *r;
	unsigned max_connections;

	max_connections = dom->obj->max_connections;
	if (max_connections > 0) {
		/* There is an explicit max_connections, so use it. */
		return max_connections;
	}

	/* Calcuate a max_connections based on current connections per backend. */
	VTAILQ_FOREACH(r, &dom->refs, list) {
		if (VRT_Healthy(ctx, r->be->dir, NULL)) {
			unsigned n_conn;
			struct backend *be;

			CAST_OBJ_NOTNULL(be, r->be->dir->priv, BACKEND_MAGIC);
			n_conn = be->n_conn;
			if (n_conn > max_connections) {
				max_connections = n_conn;
			}
		}
	}

	/* Adjust max_connections assuming we're at 80% load (so 25% bigger than our current
	   number of connections) so we indicate that there is room for more connections
	   while also staying in a sensible scale.
	 */
	max_connections = max_connections * 1.25;

	/* Ensure max_connections remains significantly higher than our slow-start max, if
	   we have one.
	 */
	if (max_connections < dom->obj->slow_start_max_connections * 2) {
		max_connections = dom->obj->slow_start_max_connections * 2;
	}

	return max_connections;
}

static const struct director * v_matchproto_(vdi_resolve_f)
dynamic_resolve_leastconn(VRT_CTX, struct dynamic_domain *dom)
{
	struct dynamic_ref *next;
	struct dynamic_ref *best_next;
	unsigned most_connections_available;
	unsigned max_connections;
	
	best_next = NULL;
	most_connections_available = 0;

	max_connections = dynamic_effective_max_connections(ctx, dom);

	VTAILQ_FOREACH(next, &dom->refs, list) {
		if (VRT_Healthy(ctx, next->be->dir, NULL)) {
			unsigned connections_available;

			connections_available = dynamic_connections_available(dom, next, max_connections);
			if (connections_available > most_connections_available) {
				best_next = next;
				most_connections_available = connections_available;
			}
		}
	}

	if (best_next != NULL) {
		assert(best_next->be->dir != NULL);
		return best_next->be->dir;
	}

	/* Fallback to RR if no connections are available. */
	return dynamic_resolve_rr(ctx, dom);
}

static const struct director * v_matchproto_(vdi_resolve_f)
dynamic_resolve_weighted_leastconn(VRT_CTX, struct dynamic_domain *dom)
{
	struct dynamic_ref *r;
	unsigned max_connections;
	unsigned total_connections_available;
	unsigned chosen_connection_number;
	double rand;
	
	total_connections_available = 0;
	max_connections = dynamic_effective_max_connections(ctx, dom);

	VTAILQ_FOREACH(r, &dom->refs, list) {
		CHECK_OBJ_NOTNULL(r->be->dir, DIRECTOR_MAGIC);

		if (VRT_Healthy(ctx, r->be->dir, NULL)) {
			unsigned connections_available;

			connections_available = dynamic_connections_available(dom, r, max_connections);
			r->weight = connections_available;
			total_connections_available += connections_available;
		} else {
			r->weight = 0;
		}
	}

	rand = scalbn(VRND_RandomTestable(), -31);
	assert(rand >= 0 && rand < 1.0);
	chosen_connection_number = total_connections_available * rand;

	total_connections_available = 0;

	VTAILQ_FOREACH(r, &dom->refs, list) {
		unsigned weight;

		CHECK_OBJ_NOTNULL(r->be->dir, DIRECTOR_MAGIC);
		
		weight = r->weight;
		if (weight > 0) {
			total_connections_available += weight;

			if (total_connections_available >= chosen_connection_number) {
				break;
			}
		}
	}

	if (r != NULL) {
		assert(r->be->dir != NULL);
		return r->be->dir;
	}

	/* Fallback to RR if no connections are available. */
	return dynamic_resolve_rr(ctx, dom);
}

static VCL_BACKEND v_matchproto_(vdi_resolve_f)
dynamic_resolve(VRT_CTX, VCL_BACKEND d)
{
	struct dynamic_domain *dom;
	VCL_BACKEND dir;
	double deadline;
	int ret;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dom, d->priv, DYNAMIC_DOMAIN_MAGIC);

	Lck_Lock(&dom->mtx);

	if (dom->status < DYNAMIC_ST_ACTIVE) {
		deadline = VTIM_real() + dom->obj->first_lookup_tmo;
		ret = Lck_CondWait(&dom->resolve, &dom->mtx, deadline);
		assert(ret == 0 || ret == ETIMEDOUT);
	}

	if (dom->status > DYNAMIC_ST_ACTIVE) {
		Lck_Unlock(&dom->mtx);
		return (NULL);
	}

	dir = NULL;
	switch (dom->obj->algorithm) {
		case WEIGHTED_LEAST:
			dir = dynamic_resolve_weighted_leastconn(ctx, dom);
			break;
		case LEAST:
			dir = dynamic_resolve_leastconn(ctx, dom);
			break;
		case RR:
			dir = dynamic_resolve_rr(ctx, dom);
			break;
	}

	Lck_Unlock(&dom->mtx);

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

	/* One healthy backend is enough for the director to be healthy */
	VTAILQ_FOREACH(r, &dom->refs, list) {
		CHECK_OBJ_NOTNULL(r->be->dir, DIRECTOR_MAGIC);
		retval = VRT_Healthy(ctx, r->be->dir, &c);
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

/*--------------------------------------------------------------------
 * Background job
 */

static void
dynamic_del(VRT_CTX, struct dynamic_ref *r)
{
	struct dynamic_domain *dom;
	struct dynamic_backend *b;
	struct vrt_ctx tmp;

	AN(r);
	CHECK_OBJ_ORNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(r->dom, DYNAMIC_DOMAIN_MAGIC);

	b = r->be;
	AN(b);
	CHECK_OBJ_NOTNULL(b->dir, DIRECTOR_MAGIC);

	dom = r->dom;

	if (ctx != NULL) {
		Lck_AssertHeld(&dom->mtx);
		Lck_AssertHeld(&dom->obj->mtx);
	}
	else {
		ASSERT_CLI();
		INIT_OBJ(&tmp, VRT_CTX_MAGIC);
		tmp.vcl = dom->obj->vcl;
		ctx = &tmp;
	}

	if (r == dom->current)
		dom->current = VTAILQ_NEXT(r, list);

	VTAILQ_REMOVE(&dom->refs, r, list);
	free(r);

	AN(b->refcount);
	b->refcount--;

	DBG(ctx, dom, "unref-backend %s (%d remaining)", b->vcl_name,
	    b->refcount);

	if (b->refcount > 0)
		return;

	DBG(ctx, dom, "delete-backend %s", b->vcl_name);

	VTAILQ_REMOVE(&dom->obj->backends, b, list);
	AN(ctx->vcl);
	VRT_delete_backend(ctx, &b->dir);

	free(b->vcl_name);
	free(b->ip_addr);
	free(b->ip_suckaddr);
	free(b);
}

static void
dynamic_ref(VRT_CTX, struct dynamic_domain *dom, struct dynamic_backend *b)
{
	struct dynamic_ref *r;

	r = malloc(sizeof *r);
	AN(r);
	memset(r, 0, sizeof *r);
	r->dom = dom;
	r->be = b;
	r->mark = dom->mark;
	b->refcount++;
	VTAILQ_INSERT_TAIL(&dom->refs, r, list);

	DBG(ctx, dom, "ref-backend %s (%d in total)", b->vcl_name,
	    b->refcount);
}

static unsigned
dynamic_find(struct dynamic_domain *dom, const struct suckaddr *sa)
{
	struct dynamic_backend *b;
	struct dynamic_ref *r;
	struct vrt_ctx ctx;

	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
	CHECK_OBJ_NOTNULL(dom->obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	INIT_OBJ(&ctx, VRT_CTX_MAGIC);

	/* search this domain's backends */
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

	if (dom->obj->share == HOST)
		return (0);

	/* search the rest of the backends */
	VTAILQ_FOREACH(b, &dom->obj->backends, list) {
		CHECK_OBJ_NOTNULL(b->dir, DIRECTOR_MAGIC);
		if (!VSA_Compare(b->ip_suckaddr, sa)) {
			dynamic_ref(&ctx, dom, b);
			return (1);
		}
	}

	return (0);
}

/* all parameters owned by caller */
static void
dynamic_add(VRT_CTX, struct dynamic_domain *dom, const struct res_info *info)
{
	struct suckaddr *sa;
	struct vrt_backend vrt;
	struct vrt_endpoint ep;
	struct dynamic_backend *b;
	struct vsb *vsb;
	char addr[VTCP_ADDRBUFSIZE];
	char port[VTCP_PORTBUFSIZE];

	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
	CHECK_OBJ_NOTNULL(dom->obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	AN(info);
	Lck_AssertHeld(&dom->mtx);
	Lck_AssertHeld(&dom->obj->mtx);

	if (dom->obj->whitelist != NULL &&
	    ! VRT_acl_match(ctx, dom->obj->whitelist, info->sa)) {
		VTCP_name(info->sa, addr, sizeof addr, port, sizeof port);
		LOG(ctx, SLT_Error, dom, "whitelist mismatch %s:%s",
		    addr, port);
		return;
	}

	if (dynamic_find(dom, info->sa))
		return;

	VTCP_name(info->sa, addr, sizeof addr, port, sizeof port);
	sa = VSA_Clone(info->sa);

	b = malloc(sizeof *b);
	AN(b);
	memset(b, 0, sizeof *b);
	b->ip_suckaddr = sa;

	b->ip_addr = strdup(addr);
	AN(b->ip_addr);

	vsb = VSB_new_auto();
	AN(vsb);

	INIT_OBJ(&vrt, VRT_BACKEND_MAGIC);

	switch (dom->obj->share) {
	case DIRECTOR:
		vrt.hosthdr = dom->obj->hosthdr;
		VSB_printf(vsb, "%s(%s:%s)", dom->obj->vcl_name, b->ip_addr,
		    dom_port(dom));
		break;
	case HOST:
		vrt.hosthdr = dom->obj->hosthdr ? dom->obj->hosthdr : dom->addr;
		VSB_printf(vsb, "%s.%s(%s:%s)", dom->obj->vcl_name, dom->addr,
		    b->ip_addr, dom_port(dom));
		break;
	default:
		INCOMPL();
	}
	AZ(VSB_finish(vsb));
	b->vcl_name = strdup(VSB_data(vsb));
	AN(b->vcl_name);
	VSB_destroy(&vsb);

	vrt.vcl_name = b->vcl_name;
	vrt.probe = dom->obj->probe;
	vrt.connect_timeout = dom->obj->connect_tmo;
	vrt.first_byte_timeout = dom->obj->first_byte_tmo;
	vrt.between_bytes_timeout = dom->obj->between_bytes_tmo;
	vrt.max_connections = dom->obj->max_connections;
	vrt.proxy_header = dom->obj->proxy_header;
	assert(vrt.proxy_header <= 2);
	INIT_OBJ(&ep, VRT_ENDPOINT_MAGIC);

	switch (VSA_Get_Proto(sa)) {
	case AF_INET:
		ep.ipv4 = sa;
		break;
	case AF_INET6:
		ep.ipv6 = sa;
		break;
	default:
		WRONG("unexpected family");
	}
	vrt.endpoint = &ep;

	b->dir = VRT_new_backend(ctx, &vrt);
	AN(b->dir);

	DBG(ctx, dom, "add-backend %s", b->vcl_name);

	dynamic_ref(ctx, dom, b);

	VTAILQ_INSERT_TAIL(&dom->obj->backends, b, list);
	return;
}

static void
dynamic_update_domain(struct dynamic_domain *dom, const struct res_cb *res,
    void *priv, vtim_real now)
{
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

	dom->mark++;

	while ((info = res->result(ibuf, priv, &state)) != NULL) {
		dynamic_add(&ctx, dom, info);
		if (info->ttl != 0 && (isnan(ttl) || info->ttl < ttl))
			ttl = info->ttl;
	}

	VTAILQ_FOREACH_SAFE(r, &dom->refs, list, r2)
		if (r->mark != dom->mark)
			dynamic_del(&ctx, r);

	Lck_Unlock(&dom->mtx);
	Lck_Unlock(&dom->obj->mtx);

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

	VSL(SLT_Timestamp, 0, "vmod-dynamic %s.%s(%s:%s) %s: %.6f %.6f %.6f",
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

	while (obj->active && dom->status <= DYNAMIC_ST_ACTIVE) {

		lookup = VTIM_real();
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

		if (dom->status == DYNAMIC_ST_READY) {
			AZ(pthread_cond_broadcast(&dom->resolve));
			dom->status = DYNAMIC_ST_ACTIVE;
		}

		/* Check status again after the blocking call */
		if (obj->active && dom->status <= DYNAMIC_ST_ACTIVE) {
			ret = Lck_CondWait(&dom->cond, &dom->mtx,
			    dom->deadline);
			assert(ret == 0 || ret == ETIMEDOUT);
		}

		Lck_Unlock(&dom->mtx);
	}

	dom->status = DYNAMIC_ST_DONE;
	dynamic_timestamp(dom, "Done", VTIM_real(), 0., 0.);

	return (NULL);
}

static void
dynamic_free(VRT_CTX, struct dynamic_domain *dom)
{

	CHECK_OBJ_ORNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
	AZ(dom->thread);
	assert(dom->status == DYNAMIC_ST_READY);

	VRT_DelDirector(&dom->dir);

	if (ctx != NULL) {
		Lck_AssertHeld(&dom->obj->mtx);
		LOG(ctx, SLT_VCL_Log, dom, "%s", "deleted");
	}

	Lck_Lock(&dom->mtx);
	while (!VTAILQ_EMPTY(&dom->refs))
		dynamic_del(ctx, VTAILQ_FIRST(&dom->refs));
	Lck_Unlock(&dom->mtx);

	AZ(pthread_cond_destroy(&dom->resolve));
	AZ(pthread_cond_destroy(&dom->cond));
	Lck_Delete(&dom->mtx);
	REPLACE(dom->addr, NULL);
	REPLACE(dom->port, NULL);
	FREE_OBJ(dom);
}

static void
dynamic_join(struct dynamic_domain *dom)
{

	CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
	AN(dom->thread);
	AZ(pthread_join(dom->thread, NULL));
	assert(dom->status == DYNAMIC_ST_DONE);
	dom->thread = 0;
	dom->status = DYNAMIC_ST_READY;
}

static void
dynamic_stop(struct vmod_dynamic_director *obj)
{
	struct dynamic_domain *dom, *d2;

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);

	service_stop(obj);

	/* NB: At this point we got a COLD event so there are no ongoing
	 * transactions. It means that remaining threads accessing obj are
	 * lookup threads. They may modify the backends list for the last
	 * time but no domain will be added or removed from the lists.
	 * Long story short: we don't need to lock the object's mutex.
	 */

	VTAILQ_FOREACH(dom, &obj->active_domains, list) {
		CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
		Lck_Lock(&dom->mtx);
		AN(dom->thread);
		AZ(pthread_cond_signal(&dom->cond));
		Lck_Unlock(&dom->mtx);
	}

	/* NB: After a call to pthread_join we know for sure that the only
	 * potential contender stopped. Therefore locking is no longer
	 * required to access a (struct dynamic_domain *)->status.
	 */

	VTAILQ_FOREACH(dom, &obj->active_domains, list)
		dynamic_join(dom);

	VTAILQ_FOREACH_SAFE(dom, &obj->purged_domains, list, d2) {
		CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
		assert(dom->status == DYNAMIC_ST_STALE ||
		    dom->status == DYNAMIC_ST_DONE);
		dynamic_join(dom);
		VTAILQ_REMOVE(&obj->purged_domains, dom, list);
		dynamic_free(NULL, dom);
	}

	VRT_VCL_Allow_Discard(&obj->vclref);
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
	VTAILQ_FOREACH(dom, &obj->active_domains, list) {
		CHECK_OBJ_NOTNULL(dom, DYNAMIC_DOMAIN_MAGIC);
		assert(dom->status == DYNAMIC_ST_READY);
		AZ(dom->thread);
		AZ(pthread_create(&dom->thread, NULL, dynamic_lookup_thread,
		    dom));
	}
	service_start(ctx, obj);
	Lck_Unlock(&obj->mtx);
}

static struct dynamic_domain *
dynamic_search(VRT_CTX, struct vmod_dynamic_director *obj, const char *addr,
    const char *port)
{
	struct dynamic_domain *dom, *d, *d2;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);
	AN(addr);

	if (port != NULL)
		AN(*port);

	dom = NULL;
	VTAILQ_FOREACH_SAFE(d, &obj->active_domains, list, d2) {
		CHECK_OBJ_NOTNULL(d, DYNAMIC_DOMAIN_MAGIC);
		if (!strcmp(d->addr, addr) &&
		    (port == NULL || !strcmp(dom_port(d), port))) {
			AZ(dom);
			dom = d;
		}
		if (dom != d && d->status == DYNAMIC_ST_ACTIVE &&
		    obj->domain_usage_tmo > 0 &&
		    ctx->now - d->last_used > obj->domain_usage_tmo) {
			LOG(ctx, SLT_VCL_Log, d, "%s", "timeout");
			Lck_Lock(&d->mtx);
			d->status = DYNAMIC_ST_STALE;
			AZ(pthread_cond_signal(&d->cond));
			Lck_Unlock(&d->mtx);
			VTAILQ_REMOVE(&obj->active_domains, d, list);
			VTAILQ_INSERT_TAIL(&obj->purged_domains, d, list);
		}
	}

	VTAILQ_FOREACH_SAFE(d, &obj->purged_domains, list, d2) {
		CHECK_OBJ_NOTNULL(d, DYNAMIC_DOMAIN_MAGIC);
		if (d->status == DYNAMIC_ST_DONE) {
			dynamic_join(d);
			VTAILQ_REMOVE(&obj->purged_domains, d, list);
			dynamic_free(ctx, d);
		}
	}

	return (dom);
}

struct dynamic_domain *
dynamic_get(VRT_CTX, struct vmod_dynamic_director *obj, const char *addr,
    const char *port)
{
	struct dynamic_domain *dom;

	CHECK_OBJ_NOTNULL(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	Lck_AssertHeld(&obj->mtx);
	AN(addr);

	dom = dynamic_search(ctx, obj, addr, port);
	if (dom != NULL)
		return (dom);

	ALLOC_OBJ(dom, DYNAMIC_DOMAIN_MAGIC);
	AN(dom);
	VTAILQ_INIT(&dom->refs);
	REPLACE(dom->addr, addr);
	REPLACE(dom->port, port);

	dom->obj = obj;

	dom->dir = VRT_AddDirector(ctx, vmod_dynamic_methods, dom,
	    "%s(%s:%s)", obj->vcl_name, addr, port);

	Lck_New(&dom->mtx, lck_be);
	AZ(pthread_cond_init(&dom->cond, NULL));
	AZ(pthread_cond_init(&dom->resolve, NULL));

	if (ctx->method != VCL_MET_INIT)
		AZ(pthread_create(&dom->thread, NULL, dynamic_lookup_thread,
			dom));

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

		assert(obj->active != active);
		obj->active = active;
		if (active)
			dynamic_start(ctx, obj);
		else
			dynamic_stop(obj);
	}
	return (0);
}

static inline enum dynamic_share_e
dynamic_share_parse(const char *share_s)
{
	switch (share_s[0]) {
	case 'D':	return DIRECTOR;
	case 'H':	return HOST;
	default:	INCOMPL();
	}
}

static inline enum dynamic_ttl_e
dynamic_ttl_parse(const char *ttl_s)
{
	switch (ttl_s[0]) {
	case 'c':	return cfg;
	case 'd':	return dns;
	default:	break;
	}
	assert(ttl_s[0] == 'm');
	switch (ttl_s[1]) {
	case 'i':	return min;
	case 'a':	return max;
	default:	break;
	}
	INCOMPL();
}

static inline enum dynamic_algorithm_e
dynamic_algorithm_parse(const char *algorithm_s)
{
	if (strcmp("RR", algorithm_s) == 0) {
		return RR;
	} else if (strcmp("LEAST", algorithm_s) == 0) {
		return LEAST;
	} else if (strcmp("WEIGHTED_LEAST", algorithm_s) == 0) {
		return WEIGHTED_LEAST;
	} else {
		INCOMPL();
		NEEDLESS(return(0));
	}
}


VCL_VOID v_matchproto_()
vmod_director__init(VRT_CTX,
    struct vmod_dynamic_director **objp,
    const char *vcl_name,
    VCL_STRING port,
    VCL_STRING hosthdr,
    VCL_ENUM share_s,
    VCL_PROBE probe,
    VCL_ACL whitelist,
    VCL_DURATION ttl,
    VCL_DURATION connect_timeout,
    VCL_DURATION first_byte_timeout,
    VCL_DURATION between_bytes_timeout,
    VCL_DURATION domain_usage_timeout,
    VCL_DURATION first_lookup_timeout,
    VCL_INT max_connections,
    VCL_INT slow_start_max_connections,
    VCL_INT slow_start_percentage,
    VCL_INT proxy_header,
    VCL_BLOB resolver,
    VCL_ENUM ttl_from_s,
	VCL_ENUM algorithm_s,
    VCL_DURATION retry_after)
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

        assert(ttl > 0);
        assert(domain_usage_timeout > 0);
        assert(first_lookup_timeout > 0);
	assert(connect_timeout >= 0);
	assert(first_byte_timeout >= 0);
	assert(between_bytes_timeout >= 0);
	assert(max_connections >= 0);
	assert(slow_start_max_connections >= 0);
	assert(proxy_header >= 0);

	ALLOC_OBJ(obj, VMOD_DYNAMIC_DIRECTOR_MAGIC);
	AN(obj);
	VTAILQ_INIT(&obj->active_domains);
	VTAILQ_INIT(&obj->purged_domains);
	VTAILQ_INIT(&obj->active_services);
	VTAILQ_INIT(&obj->purged_services);
	VTAILQ_INIT(&obj->backends);
	REPLACE(obj->vcl_name, vcl_name);
	REPLACE(obj->port, port);

	obj->vcl_conf = VCL_Name(ctx->vcl);
	obj->vcl = ctx->vcl;
	obj->active = 0;
	obj->hosthdr = hosthdr;
	obj->share = dynamic_share_parse(share_s);
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
	obj->slow_start_max_connections = (unsigned)slow_start_max_connections;
	obj->slow_start_percentage = (double)slow_start_percentage / 100.0;
	obj->proxy_header = (unsigned)proxy_header;
	obj->ttl_from = dynamic_ttl_parse(ttl_from_s);
	obj->algorithm = dynamic_algorithm_parse(algorithm_s);

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
			    ttl_from_s);
		obj->resolver = &res_gai;
	}

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

	/* Backends will be deleted by the VCL, pass a NULL struct ctx */
	VTAILQ_FOREACH_SAFE(dom, &obj->purged_domains, list, d2) {
		VTAILQ_REMOVE(&obj->purged_domains, dom, list);
		dynamic_free(NULL, dom);
	}

	VTAILQ_FOREACH_SAFE(dom, &obj->active_domains, list, d2) {
		VTAILQ_REMOVE(&obj->active_domains, dom, list);
		dynamic_free(NULL, dom);
	}

	assert(VTAILQ_EMPTY(&obj->backends));

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
	dom->last_used = ctx->now;
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
