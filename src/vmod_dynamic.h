/*-
 * Copyright (c) 2016 Varnish Software AS
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
 * Data structures
 *
 * Locking order is always vmod_dynamic_director.mtx and then dynamic_domain.mtx
 * when both are needed.
 */

extern struct VSC_lck *lck_be;

struct dynamic_backend {
	VCL_BACKEND			dir;
	VTAILQ_ENTRY(dynamic_backend)	list;
	struct suckaddr 		*ip_suckaddr;
	char				*ip_addr;
	char				*vcl_name;
	unsigned			refcount;
};

struct dynamic_ref {
	struct dynamic_domain		*dom;
	VTAILQ_ENTRY(dynamic_ref)	list;
	struct dynamic_backend		*be;
	unsigned			mark;
	unsigned			weight;
};

enum dynamic_status_e {
	DYNAMIC_ST_READY	= 0,
	DYNAMIC_ST_ACTIVE	= 1,
	DYNAMIC_ST_STALE	= 2,
	DYNAMIC_ST_DONE		= 3,
};

enum dynamic_share_e {
	DIRECTOR,
	HOST
};

enum dynamic_ttl_e {
	cfg,
	dns,
	min,
	max
};

enum dynamic_algorithm_e {
	RR,
	LEAST,
	WEIGHTED_LEAST
};

struct dynamic_domain {
	unsigned			magic;
#define DYNAMIC_DOMAIN_MAGIC		0x1bfe1345
	unsigned			mark;
	struct vmod_dynamic_director	*obj;
	pthread_t			thread;
	struct lock			mtx;
	pthread_cond_t			cond;
	pthread_cond_t			resolve;
	VCL_TIME			last_used;
	VTAILQ_ENTRY(dynamic_domain)	list;
	VTAILQ_HEAD(, dynamic_ref)	refs;
	struct dynamic_ref		*current;
	char				*addr;
	char				*port;
	VCL_BACKEND			dir;
	vtim_real			deadline;
	VCL_TIME			changed_cached;
	volatile enum dynamic_status_e	status;
	VCL_BOOL			healthy_cached;
};

struct service_target {
	unsigned			magic;
#define SERVICE_TARGET_MAGIC		0xd15e71c7
	uint32_t			weight;

	struct dynamic_domain		*dom;
	VTAILQ_ENTRY(service_target)	list;

	/* not required, debug info only */
	uint32_t			port;
	char				*target;
};

struct service_prio {
	unsigned			magic;
#define SERVICE_PRIO_MAGIC		0xd15e71c0
	uint32_t			priority;
	unsigned			n_targets;
	VTAILQ_HEAD(, service_target)	targets;
	VTAILQ_ENTRY(service_prio)	list;
};

struct service_prios {
	unsigned			magic;
#define SERVICE_PRIOS_MAGIC		0xd15e71c5
	unsigned			max_targets;
	VTAILQ_HEAD(, service_prio)	head;
};

struct dynamic_service {
	unsigned			magic;
#define DYNAMIC_SERVICE_MAGIC		0xd15e71ce
	struct vmod_dynamic_director	*obj;

	char				*service;
	VTAILQ_ENTRY(dynamic_service)	list;
	VCL_BACKEND			dir;

	VCL_TIME			last_used;
	struct lock			mtx;
	pthread_cond_t			cond;
	volatile enum dynamic_status_e	status;

	pthread_t			thread;
	pthread_cond_t			resolve;

	vtim_real			deadline;

	// swapped, membar'ed
	struct service_prios		*prios;
	// owned by service_update()
	struct service_prios		*prios_cold;
};


struct vmod_dynamic_director {
	unsigned				magic;
#define VMOD_DYNAMIC_DIRECTOR_MAGIC		0x8a3e7fd1
	struct lock				mtx;
	char					*vcl_name;
	char					*port;
	const char				*hosthdr;
	enum dynamic_share_e			share;
	VCL_PROBE				probe;
	VCL_ACL					whitelist;
	VCL_DURATION				ttl;
	VCL_DURATION				retry_after;
	VCL_DURATION				connect_tmo;
	VCL_DURATION				first_byte_tmo;
	VCL_DURATION				between_bytes_tmo;
	VCL_DURATION				domain_usage_tmo;
	VCL_DURATION				first_lookup_tmo;
	unsigned				max_connections;
	unsigned				slow_start_max_connections;
	double					slow_start_percentage;
	unsigned				proxy_header;
	VTAILQ_ENTRY(vmod_dynamic_director)	list;
	VTAILQ_HEAD(,dynamic_domain)		active_domains;
	VTAILQ_HEAD(,dynamic_domain)		purged_domains;
	VTAILQ_HEAD(,dynamic_service)		active_services;
	VTAILQ_HEAD(,dynamic_service)		purged_services;
	VTAILQ_HEAD(,dynamic_backend)		backends;
	const char				*vcl_conf;
	struct vcl				*vcl;
	struct vclref				*vclref;
	volatile unsigned			active;
	volatile unsigned			debug;
	const struct res_cb			*resolver;
	struct VPFX(dynamic_resolver)		*resolver_inst;
	enum dynamic_ttl_e			ttl_from;
	enum dynamic_algorithm_e	algorithm;
};

VTAILQ_HEAD(vmod_dynamic_head, vmod_dynamic_director);

struct dynamic_domain *
dynamic_get(VRT_CTX, struct vmod_dynamic_director *obj, const char *addr,
const char *port);

// vmod_dynamic_service.c
struct dynamic_service;
void service_stop(struct vmod_dynamic_director *obj);
void service_start(VRT_CTX, struct vmod_dynamic_director *obj);
void service_fini(struct vmod_dynamic_director *obj);

// generic

// dump details to vsl
static inline void
dbg_res_details(struct vsl_log *vsl, const struct vmod_dynamic_director *obj,
    const struct res_cb *res, void *res_priv)
{
	char *details, *line, *save;

	if (obj->debug == 0 || res == NULL || res->details == NULL)
		return;

	details = res->details(res_priv);
	if (details == NULL) {
		line = "(no details)";
		if (vsl != NULL)
			VSLb(vsl, SLT_Debug, "vmod-dynamic resolver: %s",
			    line);
		else
			VSL(SLT_Debug, 0, "vmod-dynamic resolver: %s",
			    line);
		return;
	}

	line = strtok_r(details, "\n", &save);
	while (line != NULL) {
		if (vsl != NULL)
			VSLb(vsl, SLT_Debug, "vmod-dynamic resolver: %s",
			    line);
		else
			VSL(SLT_Debug, 0, "vmod-dynamic resolver: %s",
			    line);
		line = strtok_r(NULL, "\n", &save);
	}
	free(details);
}
