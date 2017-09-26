/*-
 * Copyright (c) 2016 Varnish Software AS
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
 *
 * Data structures
 *
 * Locking order is always vmod_dynamic_director.mtx and then dynamic_domain.mtx
 * when both are needed.
 */

struct dynamic_backend {
	struct director			*dir;
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

struct dynamic_domain {
	unsigned			magic;
#define DYNAMIC_DOMAIN_MAGIC		0x1bfe1345
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
	const char			*port;
	struct director			dir;
	unsigned			mark;
	volatile enum dynamic_status_e	status;
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
	VCL_DURATION				connect_tmo;
	VCL_DURATION				first_byte_tmo;
	VCL_DURATION				between_bytes_tmo;
	VCL_DURATION				domain_usage_tmo;
	VCL_DURATION				first_lookup_tmo;
	unsigned				max_connections;
	unsigned				proxy_header;
	VTAILQ_ENTRY(vmod_dynamic_director)	list;
	VTAILQ_HEAD(,dynamic_domain)		active_domains;
	VTAILQ_HEAD(,dynamic_domain)		purged_domains;
	VTAILQ_HEAD(,dynamic_backend)		backends;
	const char				*vcl_conf;
	struct vcl				*vcl;
	struct vclref				*vclref;
	volatile unsigned			active;
	volatile unsigned			debug;
};

VTAILQ_HEAD(vmod_dynamic_head, vmod_dynamic_director) objects;

extern struct vmod_dynamic_head objects;

/* compat vdef.h */
#ifndef NEEDLESS
#ifdef __SUNPRO_C
#define NEEDLESS(s)             {}
#define __unused
#else
#define NEEDLESS(s)             s
#endif
#endif /* NEEDLESS */
