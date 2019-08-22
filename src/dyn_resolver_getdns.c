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

#ifdef __FreeBSD__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#endif

#include <cache/cache.h>
#include <vsa.h>

#include "vcc_dynamic_if.h"

#include "dyn_resolver.h"
#include "dyn_getdns.h"

/* ------------------------------------------------------------
 * getdns resolver
 */

// needs to be first in specific states so a cast works
struct dyn_getdns_common_state {
	struct VPFX(dynamic_resolver_context)	*context;
	getdns_dict				*response;
	getdns_list				*replies;
	getdns_list				*answers;
	size_t					n_replies;
	size_t					n_answers;
	size_t					reply;  // next to return
	size_t					answer; // next to return
};

struct dyn_getdns_addr_state {
	struct dyn_getdns_common_state		common;
	uint16_t				port;
};

#define errchk(ret) if (ret != GETDNS_RETURN_GOOD) return(ret)

#ifdef DUMP_GETDNS
#include <unistd.h>
#define dbg_dump_getdns(r) do {					\
		char *dbg = getdns_pretty_print_dict(r);		\
		write(2, dbg, strlen(dbg));				\
		free(dbg);						\
	} while (0)
#else
#define dbg_dump_getdns(r) (void)0
#endif

/* ------------------------------------------------------------
 * common
 */

/* look for answer in the next reply */
static int
getdns_common_more_answers(struct dyn_getdns_common_state *state)
{
	getdns_return_t ret;
	getdns_dict	*reply;

	if (state->answer < state->n_answers)
		return (0);

	state->n_answers = state->answer = 0;

	if (state->reply >= state->n_replies)
		return (GETDNS_RETURN_NO_ANSWERS);	// no *more* answers

	ret = getdns_list_get_dict(state->replies, state->reply++, &reply);
	AZ(ret);

	ret = getdns_dict_get_list(reply, "/answer", &state->answers);
	AZ(ret);

	ret = getdns_list_get_length(state->answers, &state->n_answers);

	if (state->n_answers > 0)
		return (ret);

	return (getdns_common_more_answers(state));
}

static int
getdns_common_lookup_check(struct dyn_getdns_common_state *state)
{
	getdns_return_t ret;
	uint32_t	status;

	AN(state);

	dbg_dump_getdns(state->response);

	ret = getdns_dict_get_int(state->response, "/status", &status);
	errchk(ret);

	if (status != GETDNS_RESPSTATUS_GOOD)
		return (status);

	ret = getdns_dict_get_list(state->response,
	    "/replies_tree", &state->replies);
	errchk(ret);

	ret = getdns_list_get_length(state->replies,
	    &state->n_replies);
	errchk(ret);

	if (state->n_replies == 0)
		return (GETDNS_RETURN_NO_ANSWERS);

	(void) getdns_common_more_answers(state);

	if (state->n_answers == 0)
		ret = GETDNS_RETURN_NO_ANSWERS;

	return (ret);
}

/* ------------------------------------------------------------
 * addr
 */

static int
getdns_lookup(struct VPFX(dynamic_resolver) *r,
    const char *node, const char *service, void **priv)
{
	struct VPFX(dynamic_resolver_context) *c = NULL;
	struct dyn_getdns_addr_state *addrstate;
	struct dyn_getdns_common_state *state;
	getdns_return_t ret = GETDNS_RETURN_GENERIC_ERROR;

	char		buf[1024];
	struct servent	servent_buf[1];
	struct servent	*servent;

	AN(r);
	AN(priv);
	AZ(*priv);

	addrstate = malloc(sizeof *addrstate);
	AN(addrstate);
	memset(addrstate, 0, sizeof *addrstate);
	*priv = addrstate;
	state = &addrstate->common;

	// XXX tcp hardcoded ok?
	addrstate->port = atoi(service);
	if (addrstate->port != 0)
		addrstate->port = htons(addrstate->port);
	else if (getservbyname_r(service, "tcp", servent_buf,
		     buf, sizeof(buf), &servent) != 0)
		return (GETDNS_RETURN_NO_SERVBYNAME);
	else
		addrstate->port = servent->s_port;

	c = dyn_getdns_get_context(r);
	AN(c);
	AN(c->context);
	state->context = c;

	ret = getdns_address_sync(c->context, node, NULL, &state->response);
	errchk(ret);

	return (getdns_common_lookup_check(state));
}

void *getdns_last = &getdns_last;

static struct res_info *
getdns_result(struct res_info *info, void *priv, void **answerp)
{
	struct dyn_getdns_addr_state *addrstate;
	struct dyn_getdns_common_state *state;
	getdns_dict *rr;
	getdns_bindata *addr;
	getdns_return_t ret = 0;
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;

	AN(info);
	AN(priv);
	AN(answerp);

	if (*answerp == getdns_last)
		return (NULL);

	addrstate = priv;
	state = &addrstate->common;
	if (state->answer >= state->n_answers &&
	    state->reply >= state->n_replies) {
		*answerp = getdns_last;
		return (NULL);
	} else if (*answerp == NULL) {
		*answerp = &state->answer;
	}

	assert(*answerp == &state->answer);

	while (getdns_common_more_answers(state) == 0) {
		ret = getdns_list_get_dict(state->answers,
		    state->answer++, &rr);
		AZ(ret);

		ret = getdns_dict_get_bindata(rr, "/rdata/ipv6_address", &addr);
		if (ret == 0)
			break;
		ret = getdns_dict_get_bindata(rr, "/rdata/ipv4_address", &addr);
		if (ret == 0)
			break;
	}

	if (ret != 0) {
		*answerp = getdns_last;
		return (NULL);
	}

	(void) getdns_dict_get_int(rr, "/ttl", &info->ttl);

	/* why dont the getdns folks provide with an interface to
	 * return a sockaddr ?
	 */

	switch (addr->size) {
	case 4:
		assert(sizeof sa4.sin_addr == 4);
		memset(&sa4, 0, sizeof sa4);
		sa4.sin_family = AF_INET;
		sa4.sin_port = addrstate->port;
		memcpy(&sa4.sin_addr, addr->data, addr->size);
		info->sa = VSA_Build(info->suckbuf, &sa4, sizeof sa4);
		break;
	case 16:
		assert(sizeof sa6.sin6_addr == 16);
		memset(&sa6, 0, sizeof sa6);
		sa6.sin6_family = AF_INET6;
		sa6.sin6_port = addrstate->port;
		memcpy(&sa6.sin6_addr, addr->data, addr->size);
		info->sa = VSA_Build(info->suckbuf, &sa6, sizeof sa6);
		break;
	default:
		INCOMPL();
	}
	return (info->sa != NULL ? info : NULL);
}

static void
getdns_fini(void **priv)
{
	struct dyn_getdns_addr_state *addrstate;
	struct dyn_getdns_common_state *state;

	AN(priv);
	addrstate = *priv;
	*priv = NULL;
	AN(addrstate);

	state = &addrstate->common;
	AN(state->context);
	AN(state->response);
	getdns_dict_destroy(state->response);
	dyn_getdns_rel_context(&state->context);

	free(addrstate);
}

/* ------------------------------------------------------------
 * srv
 */

struct dyn_getdns_srv_state {
	struct dyn_getdns_common_state		common;
};

static int
getdns_srv_lookup(struct VPFX(dynamic_resolver) *r,
    const char *service, void **priv)
{
	struct VPFX(dynamic_resolver_context) *c = NULL;
	struct dyn_getdns_srv_state *srvstate;
	struct dyn_getdns_common_state *state;
	getdns_return_t ret;

	AN(r);
	AN(service);
	AN(priv);
	AZ(*priv);

	srvstate = malloc(sizeof *srvstate);
	AN(srvstate);
	memset(srvstate, 0, sizeof *srvstate);
	*priv = srvstate;
	state = &srvstate->common;

	c = dyn_getdns_get_context(r);
	AN(c);
	AN(c->context);
	state->context = c;

	ret = getdns_service_sync(c->context, service, NULL, &state->response);
	errchk(ret);

	return (getdns_common_lookup_check(state));
}

static struct srv_info *
getdns_srv_result(struct srv_info *info, void *priv, void **answerp)
{
	struct dyn_getdns_srv_state *srvstate;
	struct dyn_getdns_common_state *state;
	getdns_dict *rr;
	getdns_bindata *target;
	uint32_t rrtype;
	getdns_return_t ret;

	AN(info);
	AN(priv);
	AN(answerp);

	AZ(info->target);
	memset(info, 0, sizeof *info);

	if (*answerp == getdns_last)
		return (NULL);

	srvstate = priv;
	state = &srvstate->common;
	if (state->answer >= state->n_answers &&
	    state->reply >= state->n_replies) {
		*answerp = getdns_last;
		return (NULL);
	} else if (*answerp == NULL) {
		*answerp = &state->answer;
	}

	assert(*answerp == &state->answer);

	while (getdns_common_more_answers(state) == 0) {
		ret = getdns_list_get_dict(state->answers,
		    state->answer++, &rr);
		AZ(ret);

		ret = getdns_dict_get_int(rr, "type", &rrtype);
		if (ret != 0)
			continue;

		if (rrtype != GETDNS_RRTYPE_SRV)
			continue;

		// at least target and port must be present
		ret = getdns_dict_get_bindata(rr, "/rdata/target", &target);
		if (ret != 0)
			continue;
		ret = getdns_dict_get_int(rr, "/rdata/port", &info->port);
		if (ret != 0)
			continue;

		AZ(getdns_convert_dns_name_to_fqdn(target, &info->target));
		(void) getdns_dict_get_int(rr, "/rdata/priority",
		    &info->priority);
		(void) getdns_dict_get_int(rr, "/rdata/weight",
		    &info->weight);
		(void) getdns_dict_get_int(rr, "/ttl", &info->ttl);

		return (info);
	}

	*answerp = getdns_last;
	return (NULL);
}

static void
getdns_srv_fini(void **priv)
{
	struct dyn_getdns_srv_state *srvstate;
	struct dyn_getdns_common_state *state;

	AN(priv);
	srvstate = *priv;
	*priv = NULL;
	AN(srvstate);

	state = &srvstate->common;
	AN(state->context);
	AN(state->response);
	getdns_dict_destroy(state->response);
	dyn_getdns_rel_context(&state->context);

	free(srvstate);
}

static char *
getdns_details(void *priv)
{
	struct dyn_getdns_common_state *state = priv;

	if (state == NULL || state->response == NULL)
		return (NULL);

	return (getdns_pretty_print_dict(state->response));
}

struct res_cb res_getdns = {
	.name = "getdns",

	.lookup = getdns_lookup,
	.result = getdns_result,
	.fini = getdns_fini,

	.srv_lookup = getdns_srv_lookup,
	.srv_result = getdns_srv_result,
	.srv_fini = getdns_srv_fini,

	.strerror = dyn_getdns_strerror,
	.details = getdns_details
};
