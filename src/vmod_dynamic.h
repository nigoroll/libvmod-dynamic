/*-
 * Copyright (c) 2016 Varnish Software AS
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
 *
 * Data structures
 *
 * Locking order is always vmod_dynamic_director.mtx and then dynamic_domain.mtx
 * when both are needed.
 */

#ifndef NO_VXID
#define NO_VXID (0U)
#endif

VTAILQ_HEAD(dynamic_ref_head, dynamic_ref);
VTAILQ_HEAD(dynamic_domain_head, dynamic_domain);
VTAILQ_HEAD(dynamic_service_head, dynamic_service);

extern struct VSC_lck *lck_be;

struct dynamic_ref {
	unsigned			magic;
#define DYNAMIC_REF_MAGIC		0x79a19d81
	unsigned			keep;
	VTAILQ_ENTRY(dynamic_ref)	list;
	struct dynamic_domain		*dom;
	VCL_BACKEND			dir;
	// if via is used
	const struct suckaddr		*sa;
};

enum dynamic_status_e {
	DYNAMIC_ST_READY	= 0,
	DYNAMIC_ST_STARTING,
	DYNAMIC_ST_ACTIVE,
	DYNAMIC_ST_DONE
};

enum dynamic_share_e {
	DEFAULT,
	DIRECTOR,
	HOST,
	SHARE_E_MAX
};

enum dynamic_ttl_e {
	cfg,
	dns,
	min,
	max,
	TTL_E_MAX
};

struct dynamic_domain {
	unsigned			magic;
#define DYNAMIC_DOMAIN_MAGIC		0x1bfe1345
	enum dynamic_status_e		status;
	enum vcl_event_e		last_event;
	union {
		VTAILQ_ENTRY(dynamic_domain)	list;
		VRBT_ENTRY(dynamic_domain)	tree;
	} link;
	char				*addr;
	char				*authority;
	char				*port;
	struct vmod_dynamic_director	*obj;
	pthread_t			thread;
	struct lock			mtx;
	pthread_cond_t			cond;
	pthread_cond_t			resolve;
	VCL_TIME			expires;
	VCL_TIME			deadline;
	struct dynamic_ref_head	refs, oldrefs;
	struct dynamic_ref		*current;
	VCL_BACKEND			dir;
	VCL_TIME			changed_cached;
	VCL_BOOL			healthy_cached;
};

struct service_target {
	unsigned			magic;
#define SERVICE_TARGET_MAGIC		0xd15e71c7
	uint32_t			weight;

	VCL_BACKEND			dir;
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
	enum dynamic_status_e		status;
	union {
		VTAILQ_ENTRY(dynamic_service)	list;
		VRBT_ENTRY(dynamic_service)	tree;
	} link;

	struct vmod_dynamic_director	*obj;

	char				*service;
	VCL_BACKEND			dir;

	VCL_TIME			expires;
	VCL_TIME			deadline;

	struct lock			mtx;
	pthread_cond_t			cond;

	pthread_t			thread;
	pthread_cond_t			resolve;

	// swapped, membar'ed
	struct service_prios		*prios;
	// owned by service_update()
	struct service_prios		*prios_cold;
};

VRBT_HEAD(dom_tree_head, dynamic_domain);
VRBT_HEAD(srv_tree_head, dynamic_service);

struct vmod_dynamic_director {
	unsigned				magic;
#define VMOD_DYNAMIC_DIRECTOR_MAGIC		0x8a3e7fd1
	unsigned				keep;
	char					*vcl_name;
	char					*port;
	char					*hosthdr;
	char					*authority;
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
	VCL_DURATION				wait_timeout;
	unsigned				max_connections;
	unsigned				wait_limit;
	unsigned				proxy_header;
	VCL_BACKEND				via;
	VTAILQ_ENTRY(vmod_dynamic_director)	list;

	/* ref: we hold a reference, lookup via tree
	 * unref: timed out, lose reference */
	struct lock				domains_mtx;
	struct dom_tree_head			ref_domains;
	struct dynamic_domain_head		unref_domains;

	struct lock				services_mtx;
	struct srv_tree_head			ref_services;
	struct dynamic_service_head		unref_services;

	// only to hold ctx pointer
	struct vrt_ctx				ctx[1];
	const char				*vcl_conf;
	struct vclref				*vclref;
	const struct res_cb			*resolver;
	struct VPFX(dynamic_resolver)		*resolver_inst;
	enum dynamic_ttl_e			ttl_from;
	unsigned				debug;
};

VTAILQ_HEAD(vmod_dynamic_head, vmod_dynamic_director);

void
dylog(VRT_CTX, enum VSL_tag_e slt, const char *fmt, ...) v_printflike_(3, 4);
void
dom_wait_active(struct dynamic_domain *dom);
struct dynamic_domain *
dynamic_get(VRT_CTX, struct vmod_dynamic_director *obj, const char *addr,
    const char *authority, const char *port, VCL_BACKEND *assign);

// vmod_dynamic_service.c
struct dynamic_service;
void service_stop(struct vmod_dynamic_director *obj);
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
			VSL(SLT_Debug, NO_VXID, "vmod-dynamic resolver: %s",
			    line);
		return;
	}

	line = strtok_r(details, "\n", &save);
	while (line != NULL) {
		if (vsl != NULL)
			VSLb(vsl, SLT_Debug, "vmod-dynamic resolver: %s",
			    line);
		else
			VSL(SLT_Debug, NO_VXID, "vmod-dynamic resolver: %s",
			    line);
		line = strtok_r(NULL, "\n", &save);
	}
	free(details);
}
