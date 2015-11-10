/*-
 * Copyright (c) 2015 Varnish Software AS
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

#include "vcl.h"
#include "vrt.h"

#include "cache/cache.h"
#include "cache/cache_director.h"

#include "vsa.h"
#include "vtim.h"
#include "vcc_if.h"

// no locking required, accessed only by the CLI thread
static VTAILQ_HEAD(, vmod_named_director) objects =
    VTAILQ_HEAD_INITIALIZER(objects);

struct dns_entry {
	struct dns_director		*dir;
	struct director			*backend;
	VTAILQ_ENTRY(dns_entry)		list;
	struct suckaddr 		*ip_suckaddr;
	char				*ip_addr;
	char				*vcl_name;
	unsigned			mark;
};

struct dns_director {
	unsigned			magic;
#define DNS_DIRECTOR_MAGIC		0x1bfe1345
	struct vmod_named_director	*dns;
	pthread_t			thread;
	pthread_mutex_t			mtx;
	pthread_cond_t			cond;
	pthread_cond_t			resolve;
	VTAILQ_ENTRY(dns_director)	list;
	VTAILQ_HEAD(,dns_entry)		entries;
	struct dns_entry		*current;
	char				*addr;
	const char			*port;
	struct director			dir;
	unsigned			mark;
	unsigned			lookedup;
};

struct vmod_named_director {
	unsigned				magic;
#define VMOD_NAMED_DIRECTOR_MAGIC		0x8a3e7fd1
	pthread_mutex_t				mtx;
	char					*vcl_name;
	char					*port;
	VCL_PROBE				probe;
	double					ttl;
	VTAILQ_ENTRY(vmod_named_director)	list;
	VTAILQ_HEAD(,dns_director)		directors;
	struct vcl				*vcl;
	volatile unsigned			active;
};

/*--------------------------------------------------------------------
 * Director implementation
 */

static const struct director * __match_proto__(vdi_resolve_f)
vmod_dns_resolve(const struct director *d, struct worker *wrk,
    struct busyobj *bo)
{
	struct dns_director *dir;
	struct dns_entry *next;
	struct timespec ts;
	double deadline;
	int ret;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dir, d->priv, DNS_DIRECTOR_MAGIC);

	AZ(pthread_mutex_lock(&dir->mtx));

	if (!dir->lookedup) {
		deadline = VTIM_real() + 10.; /* XXX magic timeout */
		ts = VTIM_timespec(deadline);
		ret = pthread_cond_timedwait(&dir->resolve, &dir->mtx, &ts);
		assert(ret == 0 || ret == ETIMEDOUT);
	}

	next = dir->current;

	do {
		if (next != NULL)
			next = next->list.vtqe_next;
		if (next == NULL)
			next = dir->entries.vtqh_first;
	} while (next != dir->current &&
	    !next->backend->healthy(next->backend, NULL, NULL));

	dir->current = next;

	if (next != NULL && !next->backend->healthy(next->backend, NULL, NULL))
		next = NULL;



	AZ(pthread_mutex_unlock(&dir->mtx));

	assert(next == NULL || next->backend != NULL);
	return (next == NULL ? NULL : next->backend);
}

static unsigned __match_proto__(vdi_healthy_f)
vmod_dns_healthy(const struct director *d, const struct busyobj *bo,
    double *changed)
{
	struct dns_director *dir;
	struct dns_entry *e;
	unsigned retval = 0;
	double c;

	CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(dir, d->priv, DNS_DIRECTOR_MAGIC);

	AZ(pthread_mutex_lock(&dir->mtx));

	if (changed != NULL)
		*changed = 0;

	/* One healthy backend is enough for the director to be healthy */
	VTAILQ_FOREACH(e, &dir->entries, list) {
		CHECK_OBJ_NOTNULL(e->backend, DIRECTOR_MAGIC);
		AN(e->backend->healthy);
		retval = e->backend->healthy(e->backend, bo, &c);
		if (changed != NULL && c > *changed)
			*changed = c;
		if (retval)
			break;
	}

	AZ(pthread_mutex_unlock(&dir->mtx));

	return (retval);
}

/*--------------------------------------------------------------------
 * Background job
 */

static int
vmod_dns_notfound(struct dns_director *dir, struct suckaddr *sa)
{
	struct dns_entry *e;

	AN(sa);

	VTAILQ_FOREACH(e, &dir->entries, list) {
		if (e->mark == dir->mark) /* Already visited */
			continue;

		if (VSA_Compare(e->ip_suckaddr, sa))
			continue;

		/* The mark can be invalidated by setting the probe */
		if (e->mark + 1 != dir->mark)
			return (1);

		e->mark = dir->mark;
		return (0);
	}

	return (1);
}

static void
vmod_dns_del(VRT_CTX, struct dns_entry *e)
{
	struct dns_director *dir;

	AN(e);
	CHECK_OBJ_ORNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(e->dir, DNS_DIRECTOR_MAGIC);


	dir = e->dir;

	if (e == dir->current)
		dir->current = e->list.vtqe_next;

	VTAILQ_REMOVE(&e->dir->entries, e, list);
	if (ctx) {
		AN(ctx->vcl);
		VRT_delete_backend(ctx, &e->backend);
	}
	free(e->vcl_name);
	free(e->ip_addr);
	free(e->ip_suckaddr);
	free(e);
}

static void
vmod_dns_add(VRT_CTX, struct dns_director *dir, struct suckaddr *sa)
{
	struct vrt_backend vrt;
	struct dns_entry *e;
	struct vsb *vsb;
	const unsigned char *ptr = NULL;
	char ip[INET6_ADDRSTRLEN];
	int af;

	e = malloc(sizeof *e);
	AN(e);
	e->dir = dir;
	e->mark = dir->mark;
	e->ip_suckaddr = sa;

	af = VRT_VSA_GetPtr(sa, &ptr);
	AN(ptr);
	AN(inet_ntop(af, ptr, ip, sizeof ip));
	e->ip_addr = strdup(ip);
	AN(e->ip_addr);

	vsb = VSB_new_auto();
	AN(vsb);
	VSB_printf(vsb, "%s(%s,%s)", dir->dns->vcl_name, dir->addr,
	    e->ip_addr);
	AZ(VSB_finish(vsb));

	e->vcl_name = strdup(VSB_data(vsb));
	AN(e->vcl_name);
	VSB_delete(vsb);

	INIT_OBJ(&vrt, VRT_BACKEND_MAGIC);
	vrt.port = dir->port;
	vrt.hosthdr = dir->addr;
	vrt.vcl_name = e->vcl_name;
	vrt.probe = dir->dns->probe;

	switch (af) {
	case AF_INET:
		vrt.ipv4_suckaddr = sa;
		vrt.ipv4_addr = e->ip_addr;
		break;
	case AF_INET6:
		vrt.ipv6_suckaddr = sa;
		vrt.ipv6_addr = e->ip_addr;
		break;
	default:
		WRONG("unexpected family");
	}

	/* XXX We shouldn't need this check, but since the VCL can go
	 * cold behind our back, we have no choice. It is illegal to
	 * add a backend to a cold VCL.
	 */
	if (!dir->dns->active) {
		free(e->vcl_name);
		free(e->ip_addr);
		free(e);
		return;
	}

	/* XXX Abandon all hope, ye who enter here.
	 *
	 * Despite all the safety nets, we have no guarantee it won't crash.
	 */
	e->backend = VRT_new_backend(ctx, &vrt);
	AN(e->backend);

	VTAILQ_INSERT_TAIL(&dir->entries, e, list);
}

static void
vmod_dns_update(struct dns_director *dir, struct addrinfo *addr)
{
	struct suckaddr *sa;
	struct dns_entry *e, *e2;
	struct vrt_ctx ctx;

	AN(addr);

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = dir->dns->vcl;

	dir->mark++;
	while (addr) {
		/* XXX We shouldn't need this check, but since the VCL can go
		 * cold behind our back, we have no choice. It is illegal to
		 * add a backend to a cold VCL.
		 */
		if (!dir->dns->active)
			return;

		switch (addr->ai_family) {
		case AF_INET:
		case AF_INET6:
			sa = malloc(vsa_suckaddr_len);
			AN(sa);
			AN(VSA_Build(sa, addr->ai_addr, addr->ai_addrlen));
			if (vmod_dns_notfound(dir, sa))
				vmod_dns_add(&ctx, dir, sa);
			else
				free(sa);
		}
		addr = addr->ai_next;
	}

	VTAILQ_FOREACH_SAFE(e, &dir->entries, list, e2)
		if (e->mark != dir->mark)
			vmod_dns_del(&ctx, e);
}

static void*
vmod_dns_lookup_thread(void *obj)
{
	struct dns_director *dir;
	struct vrt_ctx ctx;
	struct timespec ts;
	struct addrinfo hints, *res;
	double deadline;
	int ret;

	CAST_OBJ_NOTNULL(dir, obj, DNS_DIRECTOR_MAGIC);

	memset(&hints, 0, sizeof hints);
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;

	while (dir->dns->active) {

		ret = getaddrinfo(dir->addr, dir->dns->port, &hints, &res);

		AZ(pthread_mutex_lock(&dir->mtx));

		if (ret == 0) {
			vmod_dns_update(dir, res);
			freeaddrinfo(res);
		}
		else
			VSL(SLT_Error, 0, "DNS lookup failed: %d (%s)",
			    ret, gai_strerror(ret));

		if (!dir->lookedup) {
			AZ(pthread_cond_broadcast(&dir->resolve));
			dir->lookedup = 1;
		}

		/* Check status again after the blocking call */
		if (!dir->dns->active) {
			AZ(pthread_mutex_unlock(&dir->mtx));
			break;
		}

		deadline = VTIM_real() + dir->dns->ttl;
		ts = VTIM_timespec(deadline);
		ret = pthread_cond_timedwait(&dir->cond, &dir->mtx, &ts);
		assert(ret == 0 || ret == ETIMEDOUT);

		AZ(pthread_mutex_unlock(&dir->mtx));
	}

	INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	ctx.vcl = dir->dns->vcl;

	/* XXX At this point we should release the VCL, so that it could
	 * transition from cooling to cold. The consequence is that a cooling
	 * VCL could become warm again while the VMOD's cleanup is still in
	 * progress.
	 *
	 * Suggested API:
	 * VRT_rel_vcl(&ctx);
	 */

	AZ(pthread_mutex_lock(&dir->mtx));
	dir->thread = 0;
	AZ(pthread_mutex_unlock(&dir->mtx));

	return (NULL);
}

static void
vmod_dns_stop(struct vmod_named_director *dns)
{
	struct dns_director *dir;

	VTAILQ_FOREACH(dir, &dns->directors, list) {
		CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
		AZ(pthread_mutex_lock(&dir->mtx));
		AN(dir->thread);
		AZ(pthread_mutex_unlock(&dir->mtx));

		AZ(pthread_cond_signal(&dir->cond));
	}
}

static void
vmod_dns_start(struct vmod_named_director *dns)
{
	struct dns_director *dir;

	VTAILQ_FOREACH(dir, &dns->directors, list) {
		CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
		AZ(pthread_mutex_lock(&dir->mtx));
		AZ(dir->thread);
		AZ(pthread_mutex_unlock(&dir->mtx));

		AZ(pthread_create(&dir->thread, NULL, &vmod_dns_lookup_thread,
		    dir));
	}

	/* XXX At this point, we should acquire a reference on the VCL to
	 * prevent it from completely cooling down before the VMOD releases
	 * all its resources. VMODs running background jobs are currently
	 * exposed to spurious temperature changes before they reach a stable
	 * state.
	 *
	 * Suggested API:
	 * struct vrt_ctx ctx;
	 * INIT_OBJ(&ctx, VRT_CTX_MAGIC);
	 * ctx.vcl = dns->vcl;
	 * VRT_ref_vcl(&ctx);
	 */
}

static void
vmod_dns_free(VRT_CTX, struct dns_director *dir)
{

	CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
	AZ(dir->thread);

	VTAILQ_REMOVE(&dir->dns->directors, dir, list);
	while (dir->entries.vtqh_first != NULL)
		vmod_dns_del(ctx, dir->entries.vtqh_first);

	AZ(pthread_cond_destroy(&dir->resolve));
	AZ(pthread_cond_destroy(&dir->cond));
	AZ(pthread_mutex_destroy(&dir->mtx));
	free(dir->addr);
	FREE_OBJ(dir);
}

static struct dns_director *
vmod_dns_get(VRT_CTX, struct vmod_named_director *dns, const char *addr)
{
	struct dns_director *dir;

	CHECK_OBJ_NOTNULL(dns, VMOD_NAMED_DIRECTOR_MAGIC);
	AN(addr);

	VTAILQ_FOREACH(dir, &dns->directors, list) {
		CHECK_OBJ_NOTNULL(dir, DNS_DIRECTOR_MAGIC);
		if (strcmp(dir->addr, addr))
			continue;
		if (strcmp(dir->port, dns->port))
			continue;
		(void)ctx; // XXX log director reuse
		return dir;
	}

	ALLOC_OBJ(dir, DNS_DIRECTOR_MAGIC);
	VTAILQ_INIT(&dir->entries);
	REPLACE(dir->addr, addr);
	dir->port = dns->port;
	dir->dns = dns;

	INIT_OBJ(&dir->dir, DIRECTOR_MAGIC);
	dir->dir.name = "dns";
	dir->dir.vcl_name = dir->dns->vcl_name;
	dir->dir.healthy = vmod_dns_healthy;
	dir->dir.resolve = vmod_dns_resolve;
	dir->dir.priv = dir;

	AZ(pthread_mutex_init(&dir->mtx, NULL));
	AZ(pthread_cond_init(&dir->cond, NULL));
	AZ(pthread_cond_init(&dir->resolve, NULL));

	AZ(pthread_create(&dir->thread, NULL, &vmod_dns_lookup_thread, dir));

	return dir;
}

/*--------------------------------------------------------------------
 * VMOD interfaces
 */

int __match_proto__(vmod_event_f)
vmod_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	struct vmod_named_director *dns;
	unsigned active;

	(void)priv;

	ASSERT_CLI();
	AN(ctx);
	AN(ctx->vcl);

	/* The DNS director has no business with the other events */
	if (e != VCL_EVENT_WARM && e!= VCL_EVENT_COLD)
		return (0);

	active = e == VCL_EVENT_WARM ? 1 : 0;

	/* No locking required for the fields dns->active and dns->vcl */
	VTAILQ_FOREACH(dns, &objects, list)
		if (dns->vcl == ctx->vcl) {
			xxxassert(dns->active != active);
			dns->active = active;
			if (active)
				vmod_dns_start(dns);
			else
				vmod_dns_stop(dns);
		}

	return (0);
}

VCL_VOID __match_proto__()
vmod_director__init(VRT_CTX, struct vmod_named_director **dnsp,
    const char *vcl_name, VCL_STRING port)
{
	struct vmod_named_director *dns;

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(dnsp);
	AZ(*dnsp);
	AN(vcl_name);
	AN(port);

	ALLOC_OBJ(dns, VMOD_NAMED_DIRECTOR_MAGIC);
	AN(dns);
	VTAILQ_INIT(&dns->directors);
	REPLACE(dns->vcl_name, vcl_name);
	REPLACE(dns->port, port);

	dns->vcl = ctx->vcl;
	dns->active = 0;
	dns->probe = NULL;
	dns->ttl = 3600;

	AZ(pthread_mutex_init(&dns->mtx, NULL));

	VTAILQ_INSERT_TAIL(&objects, dns, list);
	*dnsp = dns;
}

VCL_VOID __match_proto__()
vmod_director__fini(struct vmod_named_director **dnsp)
{
	struct vmod_named_director *dns;

	ASSERT_CLI();
	AN(dnsp);
	dns = *dnsp;
	*dnsp = NULL;

	CHECK_OBJ_NOTNULL(dns, VMOD_NAMED_DIRECTOR_MAGIC);
	AZ(dns->active);

	VTAILQ_REMOVE(&objects, dns, list);

	/* Backends will be deleted by the VCL, pass a NULL struct ctx */
	while (dns->directors.vtqh_first != NULL)
		vmod_dns_free(NULL, dns->directors.vtqh_first);

	AZ(pthread_mutex_destroy(&dns->mtx));
	free(dns->vcl_name);
	FREE_OBJ(dns);
}

VCL_VOID __match_proto__()
vmod_director_probe_with(VRT_CTX, struct vmod_named_director *dns, VCL_PROBE probe)
{
	struct dns_director *dir;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(dns, VMOD_NAMED_DIRECTOR_MAGIC);
	CHECK_OBJ_NOTNULL(probe, VRT_BACKEND_PROBE_MAGIC);

	if (dns->probe == probe)
		return;

	dns->probe = probe;

	/* Force a backend refresh on the next lookup */
	AZ(pthread_mutex_lock(&dns->mtx));
	VTAILQ_FOREACH(dir, &dns->directors, list)
		dir->mark++;
	AZ(pthread_mutex_unlock(&dns->mtx));
}

VCL_VOID __match_proto__()
vmod_director_set_ttl(VRT_CTX, struct vmod_named_director *dns, VCL_DURATION ttl)
{

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(dns, VMOD_NAMED_DIRECTOR_MAGIC);
	assert(ttl > 0);
	AZ(pthread_mutex_lock(&dns->mtx));
	dns->ttl = ttl;
	AZ(pthread_mutex_unlock(&dns->mtx));
}

VCL_BACKEND __match_proto__()
vmod_director_backend(VRT_CTX, struct vmod_named_director *dns, VCL_STRING host)
{
	struct dns_director *dir;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(dns, VMOD_NAMED_DIRECTOR_MAGIC);

	AZ(pthread_mutex_lock(&dns->mtx));
	dir = vmod_dns_get(ctx, dns, host);
	AZ(pthread_mutex_unlock(&dns->mtx));

	return (&dir->dir);
}
