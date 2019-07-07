// additional interfaces between vmod and getdns

#include "getdns/getdns.h"

//struct VPFX(dynamic_resolver);

struct VPFX(dynamic_resolver_context);

struct VPFX(dynamic_resolver_context) {
	unsigned					magic;
#define DYNAMIC_RESOLVER_CONTEXT_MAGIC			0x01631d25
	VSTAILQ_ENTRY(VPFX(dynamic_resolver_context))	list;
	getdns_context					*context;
};

struct VPFX(dynamic_resolver) {
	unsigned					magic;
#define DYNAMIC_RESOLVER_MAGIC				0x00631d25
	int						n_contexts;
	char						*vcl_name;
	VSTAILQ_HEAD(,VPFX(dynamic_resolver_context))	contexts;
	pthread_mutex_t				mtx;
	pthread_cond_t					cond;
	struct VPFX(dynamic_resolver_context)		*freeptr;
};

const char * dyn_getdns_strerror(getdns_return_t);
