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
 * Locking order is always vmod_named_director.mtx and then named_domain.mtx
 * when both are needed.
 */

struct named_backend {
	struct director			*dir;
	VTAILQ_ENTRY(named_backend)	dns_list;
	struct suckaddr 		*ip_suckaddr;
	char				*ip_addr;
	char				*vcl_name;
	unsigned			refcount;
};

struct named_ref {
	struct named_domain	*dom;
	VTAILQ_ENTRY(named_ref)	dir_list;
	struct named_backend	*be;
	unsigned		mark;
};

enum named_status_e {
	NAMED_ST_READY	= 0,
	NAMED_ST_ACTIVE	= 1,
	NAMED_ST_STALE	= 2,
	NAMED_ST_DONE	= 3,
};

struct named_domain {
	unsigned			magic;
#define NAMED_DOMAIN_MAGIC		0x1bfe1345
	struct vmod_named_director	*obj;
	pthread_t			thread;
	struct lock			mtx;
	pthread_cond_t			cond;
	pthread_cond_t			resolve;
	VCL_TIME			last_used;
	VTAILQ_ENTRY(named_domain)	list;
	VTAILQ_HEAD(,named_ref)		refs;
	struct named_ref		*current;
	char				*addr;
	const char			*port;
	struct director			dir;
	unsigned			mark;
	volatile enum named_status_e	status;
};

struct vmod_named_director {
	unsigned				magic;
#define VMOD_NAMED_DIRECTOR_MAGIC		0x8a3e7fd1
	struct lock				mtx;
	char					*vcl_name;
	char					*port;
	VCL_PROBE				probe;
	VCL_ACL					whitelist;
	VCL_DURATION				ttl;
	VCL_DURATION				usage_tmo;
	VCL_DURATION				first_tmo;
	VTAILQ_ENTRY(vmod_named_director)	list;
	VTAILQ_HEAD(,named_domain)		active_domains;
	VTAILQ_HEAD(,named_domain)		purged_domains;
	VTAILQ_HEAD(,named_backend)		backends;
	const char				*vcl_conf;
	struct vcl				*vcl;
	struct vclref				*vclref;
	volatile unsigned			active;
};

VTAILQ_HEAD(vmod_named_head, vmod_named_director) objects;

extern struct vmod_named_head objects;
