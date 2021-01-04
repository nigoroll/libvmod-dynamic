/*-
 * Copyright 2019 UPLEX - Nils Goroll Systemoptimierung
 * All rights reserved.
 *
 * Authors: Nils Goroll <nils.goroll@uplex.de>
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

// interface between dynamic and resolver

#define DYNAMIC_RESOLVER_BLOB	0xf0631d25
struct VPFX(dynamic_resolver);
// implemented in vmod_resolver.c / vmod_resolver.sub.c
struct VPFX(dynamic_resolver) * dyn_resolver_blob(VCL_BLOB);

// info returned by resolver
struct res_info {
	uint8_t	*suckbuf; // vsa_suckaddr_len
	struct suckaddr	*sa; // == suckbuf on success
	uint32_t		ttl; // 0 for unset
};
struct srv_info {
	char			*target;	// must be freed!
	uint32_t		port;
	uint32_t		priority;
	uint32_t		weight;
	uint32_t		ttl; // 0 for unset
};

// A/AAAA
typedef int res_lookup_f(struct VPFX(dynamic_resolver) *r,
    const char *node, const char *service, void **priv);
typedef struct res_info *res_result_f(struct res_info *,
    void *priv, void **state);
typedef void res_fini_f(void **priv);

// SRV
typedef int srv_lookup_f(struct VPFX(dynamic_resolver) *r,
    const char *service, void **priv);
typedef struct srv_info *srv_result_f(struct srv_info *,
    void *priv, void **state);
typedef void srv_fini_f(void **priv);

// generic
typedef const char *res_strerror_f(int);
typedef char *res_details_f(void *priv); // to be freed by caller

// resolver callbacks
struct res_cb {
	const char	*name;

	res_lookup_f	*lookup;
	res_result_f	*result;
	res_fini_f	*fini;

	srv_lookup_f	*srv_lookup;
	srv_result_f	*srv_result;
	srv_fini_f	*srv_fini;

	res_strerror_f	*strerror;
	res_details_f	*details;
};

extern const struct res_cb res_gai;
extern const struct res_cb res_getdns;
