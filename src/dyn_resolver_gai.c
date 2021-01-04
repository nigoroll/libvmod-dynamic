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

#include <string.h>	// miniobj.h
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cache/cache.h>
#include <vsa.h>

#include "vcc_dynamic_if.h"

#include "dyn_resolver.h"

/* ------------------------------------------------------------
 * default getaddrinfo resolver
 */

static const struct addrinfo gai_hints = {
	.ai_socktype = SOCK_STREAM,
	.ai_family = AF_UNSPEC
};

static int
gai_lookup(struct VPFX(dynamic_resolver) *r,
    const char *node, const char *service, void **priv)
{
	AZ(r);
	AN(priv);
	AZ(*priv);

	return (getaddrinfo(node, service, &gai_hints,
	    (struct addrinfo **)priv));
}

static void *gai_last = &gai_last;

static struct res_info *
gai_result(struct res_info *info, void *priv, void **state)
{
	struct addrinfo *addr;

	AN(info);
	AN(priv);
	AN(state);

	if (*state == gai_last)
		return (NULL);

	addr = (*state != NULL) ? *state : priv;

	while (addr != NULL) {
		if (addr->ai_family == AF_INET || addr->ai_family == AF_INET6)
			break;
		addr = addr->ai_next;
	}

	if (addr == NULL) {
		*state = gai_last;
		return (NULL);
	}

	*state = (addr->ai_next == NULL) ? gai_last : addr->ai_next;

	info->sa = VSA_Build(info->suckbuf, addr->ai_addr, addr->ai_addrlen);

	return (info->sa != NULL ? info : NULL);
}

static void
gai_fini(void **priv)
{
	struct addrinfo *res;

	AN(priv);
	res = *priv;
	*priv = NULL;
	if (res != NULL)
		freeaddrinfo(res);
}

const struct res_cb res_gai = {
	.name = "getaddrinfo",
	.lookup = gai_lookup,
	.result = gai_result,
	.fini = gai_fini,
	.strerror = gai_strerror
};
