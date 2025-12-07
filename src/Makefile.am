AM_CFLAGS = $(VARNISHAPI_CFLAGS) $(GETDNS_CFLAGS) -Wall -Werror

# Modules

vmod_LTLIBRARIES = libvmod_dynamic.la

libvmod_dynamic_la_LDFLAGS = $(VARNISHAPI_LIBS) $(GETDNS_LIBS) $(VMOD_LDFLAGS)

libvmod_dynamic_la_SOURCES = \
	vmod_dynamic.h \
	vmod_dynamic.c \
	dyn_resolver.h \
	dyn_resolver_gai.c \
	vmb.h \
	vmod_dynamic_service.c

if HAVE_GETDNS
libvmod_dynamic_la_SOURCES += \
	vmod_resolver.c \
	dyn_getdns.h \
	dyn_getdns.c \
	dyn_resolver_getdns.c \
	tbl/enum/res_transport.h \
	tbl/enum/res_resolution_type.h \
	tbl/enum/res_namespace.h \
	tbl/enum/res_redirects.h \
	tbl/list_prop.h \
	tbl/getdns_return.h
else
libvmod_dynamic_la_SOURCES += vmod_resolver.stub.c
endif

nodist_libvmod_dynamic_la_SOURCES = \
	vcc_dynamic_if.c \
	vcc_dynamic_if.h

vmod_vcs_version.txt: vcc_dynamic_if.c

DISTCLEANFILES = vmod_vcs_version.txt

$(srcdir)/dyn_getdns.c: vcc_dynamic_if.h
$(srcdir)/dyn_resolver_gai.c: vcc_dynamic_if.h
$(srcdir)/dyn_resolver_getdns.c: vcc_dynamic_if.h
$(srcdir)/vmod_dynamic.c: vcc_dynamic_if.h
$(srcdir)/vmod_dynamic_service.c: vcc_dynamic_if.h
$(srcdir)/vmod_resolver.c: vcc_dynamic_if.h
$(srcdir)/vmod_resolver.stub.c: vcc_dynamic_if.h

@BUILD_VMOD_DYNAMIC@

AM_TESTS_ENVIRONMENT = \
	PATH="$(abs_builddir):$(VARNISH_TEST_PATH):$(PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -vl
AM_VTC_LOG_FLAGS = \
	-p vcl_path="$(abs_top_srcdir)/vcl:$(VARNISHAPI_VCLDIR)" \
	-p vmod_path="$(abs_builddir)/.libs:$(vmoddir):$(VARNISHAPI_VMODDIR)"

TESTS = \
	@VTC_TESTS@

# Documentation

dist_doc_DATA = \
	vmod_dynamic.vcc \
	$(TESTS)

if HAVE_VCS_VMOD_VERSION
dist_doc_DATA += vmod_vcs_version.txt
endif

dist_man_MANS = \
	vmod_dynamic.3

pdf-local: vmod_dynamic.pdf

.rst.pdf:
	rst2pdf $< $@

.rst.1:
	$(AM_V_GEN) $(RST2MAN) $< $@
