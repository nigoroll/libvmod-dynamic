/* getdns interface STUB */

#include "config.h"

#include <cache/cache.h>

#include "vcc_dynamic_if.h"

/* XXX better place? */
#include "dyn_resolver.h"
const struct res_cb res_getdns = { 0 };
/* XXX end */

struct VPFX(dynamic_resolver) {
	int dummy;
};

struct VPFX(dynamic_resolver) *
dyn_resolver_blob(VCL_BLOB blob)
{
	(void) blob;
	return (NULL);
}

VCL_VOID
vmod_resolver__init(VRT_CTX,
    struct VPFX(dynamic_resolver) **rp, const char *vcl_name,
    VCL_BOOL set_from_os, VCL_INT parallel)
{

	VRT_fail(ctx, "dynamic.resolver() not available, vmod was "
	   "built without getdns support");
	*rp = NULL;
	(void) vcl_name;
	(void) set_from_os;
	(void) parallel;
}
VCL_VOID
vmod_resolver__fini(struct VPFX(dynamic_resolver) **rp)
{
	(void) rp;
	assert(0);
}

VCL_BLOB
vmod_resolver_use(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	(void) ctx;
	(void) r;
	return (NULL);
}

VCL_BOOL
vmod_resolver_set_resolution_type(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM type_e)
{
	(void) ctx;
	(void) r;
	(void) type_e;
	return (0);
}

VCL_BOOL
vmod_resolver_clear_namespaces(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	(void) ctx;
	(void) r;
	return (0);
}

VCL_BOOL
vmod_resolver_add_namespace(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM namespace_e)
{
	(void) ctx;
	(void) r;
	(void) namespace_e;
	return (0);
}

VCL_BOOL
vmod_resolver_set_namespaces(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	(void) ctx;
	(void) r;
	return (0);
}

VCL_BOOL
vmod_resolver_clear_transports(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	(void) ctx;
	(void) r;
	return (0);
}

VCL_BOOL
vmod_resolver_add_transport(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM transport_e)
{
	(void) ctx;
	(void) r;
	(void) transport_e;
	return (0);
}

VCL_BOOL
vmod_resolver_set_transports(VRT_CTX,
    struct VPFX(dynamic_resolver) *r)
{
	(void) ctx;
	(void) r;
	return (0);
}

VCL_BOOL
vmod_resolver_set_idle_timeout(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_DURATION d)
{
	(void) ctx;
	(void) r;
	(void) d;
	return (0);
}

VCL_BOOL
vmod_resolver_set_limit_outstanding_queries(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_INT limit)
{
	(void) ctx;
	(void) r;
	(void) limit;
	return (0);
}

VCL_BOOL
vmod_resolver_set_timeout(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_DURATION d)
{
	(void) ctx;
	(void) r;
	(void) d;
	return (0);
}

VCL_BOOL
vmod_resolver_set_follow_redirects(VRT_CTX,
    struct VPFX(dynamic_resolver) *r, VCL_ENUM redirects_e)
{
	(void) ctx;
	(void) r;
	(void) redirects_e;
	return (0);
}
