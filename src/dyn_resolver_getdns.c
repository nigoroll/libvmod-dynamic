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

#include "config.h"

#include <string.h>
//#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cache/cache.h>
#include <vsa.h>

#include "vcc_dynamic_if.h"

#include "dyn_resolver.h"
#include "dyn_getdns.h"

/* ------------------------------------------------------------
 * getdns resolver
 */

struct dyn_getdns_state {
	struct VPFX(dynamic_resolver_context)	*context;
	getdns_dict				*response;
	getdns_list				*answers;
	size_t					n_answers;
	size_t					answer;	// next to return
	uint16_t				port;
};

#define errchk(ret) if (ret != GETDNS_RETURN_GOOD) goto out

#include <unistd.h>	// DEBUG XXX

static int
getdns_lookup(struct VPFX(dynamic_resolver) *r,
    const char *node, const char *service, void **priv)
{
	struct VPFX(dynamic_resolver_context) *c = NULL;
	struct dyn_getdns_state *state;
	getdns_return_t ret = GETDNS_RETURN_GENERIC_ERROR;

	char		buf[1024];
	struct servent	servent_buf[1];
	struct servent	*servent;

	AN(r);
	AN(priv);
	AZ(*priv);

	state = malloc(sizeof *state);
	AN(state);
	memset(state, 0, sizeof *state);

	// XXX tcp hardcoded ok?
	state->port = atoi(service);
	if (state->port != 0) {
		state->port = htons(state->port);
	} else if (getservbyname_r(service, "tcp", servent_buf,
	    buf, sizeof(buf), &servent) != 0) {
		ret = GETDNS_RETURN_NO_SERVBYNAME;
		goto out;
	} else {
		state->port = servent->s_port;
	}

	c = dyn_getdns_get_context(r);
	AN(c);
	AN(c->context);
	state->context = c;

	ret = getdns_address_sync(c->context, node, NULL, &state->response);
	errchk(ret);

	ret = getdns_dict_get_list(state->response,
	    "just_address_answers", &state->answers);
	errchk(ret);

	char *dbg = getdns_pretty_print_dict(state->response);
	write(2, dbg, strlen(dbg));

	ret = getdns_list_get_length(state->answers, &state->n_answers);
	errchk(ret);

	if (state->n_answers == 0)
		ret = GETDNS_RETURN_NO_ANSWERS;

  out:
	if (ret == GETDNS_RETURN_GOOD) {
		*priv = state;
		return (ret);
	}

	if (state->response != NULL)
		getdns_dict_destroy(state->response);
	if (c != NULL)
		dyn_getdns_rel_context(&c);
	free(state);
	return (ret);
}

void *getdns_last = &getdns_last;

static struct suckaddr *
getdns_result(uint8_t *buf, size_t len, void *priv, void **answerp)
{
	struct dyn_getdns_state *state;
	getdns_dict *rr;
	getdns_bindata *addr;
	getdns_return_t ret;
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;

	AN(buf);
	assert(len >= vsa_suckaddr_len);
	AN(priv);
	AN(answerp);

	if (*answerp == getdns_last)
		return (NULL);

	state = priv;
	if (state->answer >= state->n_answers) {
		*answerp = getdns_last;
		return (NULL);
	} else if (*answerp == NULL) {
		*answerp = &state->answer;
	}

	assert(*answerp == &state->answer);

	ret = getdns_list_get_dict(state->answers, state->answer++, &rr);
	AZ(ret);
	ret = getdns_dict_get_bindata(rr, "address_data", &addr);
	AZ(ret);

	/* why dont the getdns folks provide with an interface to
	 * return a sockaddr ?
	 */

	switch (addr->size) {
	case 4:
		assert(sizeof sa4.sin_addr == 4);
		memset(&sa4, 0, sizeof sa4);
		sa4.sin_family = AF_INET;
		sa4.sin_port = state->port;
		memcpy(&sa4.sin_addr, addr->data, addr->size);
		return (VSA_Build(buf, &sa4, sizeof sa4));
	case 16:
		assert(sizeof sa6.sin6_addr == 16);
		memset(&sa6, 0, sizeof sa6);
		sa6.sin6_family = AF_INET6;
		sa6.sin6_port = state->port;
		memcpy(&sa6.sin6_addr, addr->data, addr->size);
		return (VSA_Build(buf, &sa6, sizeof sa6));
	default:
		INCOMPL();
	}
	return (NULL);
}

static void
getdns_fini(void **priv)
{
	struct dyn_getdns_state *state;

	AN(priv);
	state = *priv;
	*priv = NULL;
	AN(state);

	AN(state->context);
	AN(state->response);
	AN(state->answers);	// not to be freed, refs response

	getdns_dict_destroy(state->response);
	dyn_getdns_rel_context(&state->context);
	free(state);
}

struct res_cb res_getdns = {
	.name = "getdns",
	.lookup = getdns_lookup,
	.result = getdns_result,
	.fini = getdns_fini,
	.strerror = dyn_getdns_strerror
};
