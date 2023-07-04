/* properties to be listed in backend.list -jp */

/*lint -save -e525 -e539 */

DIRPROP("port",		"\"%s\"",obj->port)
DIRPROP("hosthdr",		"\"%s\"",obj->hosthdr ? obj->hosthdr : "")
DIRPROP("share",		"\"%s\"",share_s[obj->share])
DIRPROP("probe",		"%s",	obj->probe ? "true" : "false")
DIRPROP("whitelist",		"%s",	obj->whitelist ? "true" : "false")
DIRPROP("connect_timeout",	"%.2f", obj->connect_tmo)
DIRPROP("first_byte_timeout",	"%.2f", obj->first_byte_tmo)
DIRPROP("between_bytes_timeout","%.2f", obj->between_bytes_tmo)
DIRPROP("domain_usage_timeout", "%.2f", obj->domain_usage_tmo)
DIRPROP("first_lookup_timeout", "%.2f", obj->first_lookup_tmo)
DIRPROP("max_connections",	"%u",	obj->max_connections)
DIRPROP("proxy_header",	"%u",	obj->proxy_header)
DIRPROP("resolver",		"\"%s\"",obj->resolver ? obj->resolver->name : "")
DIRPROP("retry_after",		"%.2f", obj->retry_after)
DIRPROP("via",			"\"%s\"",obj->via ? obj->via->vcl_name : "")
DIRPROP("ttl_from",		"\"%s\"",ttl_s[obj->ttl_from])
DIRPROP("ttl",			"%.2f", obj->ttl)
DIRPROP("keep",		"%u",	obj->keep)
#undef DIRPROP

/*lint -restore */
