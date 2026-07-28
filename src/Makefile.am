AM_CFLAGS = $(VINYLAPI_CFLAGS) $(GETDNS_CFLAGS) -Wall -Werror

# Modules

vmod_LTLIBRARIES = libvmod_dynamic.la

libvmod_dynamic_la_LDFLAGS = $(VINYLAPI_LIBS) $(GETDNS_LIBS) $(VMOD_LDFLAGS)

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
	PATH="$(abs_builddir):$(VINYL_TEST_PATH):$(PATH)" \
	LD_LIBRARY_PATH="$(VINYL_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = vinyltest -vl
AM_VTC_LOG_FLAGS = \
	-p vcl_path="$(abs_top_srcdir)/vcl:$(VINYLAPI_VCLDIR)" \
	-p vmod_path="$(abs_builddir)/.libs:$(vmoddir):$(VINYLAPI_VMODDIR)"

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

# Code coverage

GCOV_PREFIX ?= $(builddir)/coverage

gcov: clean
	$(AM_V_at)@mkdir -p $(GCOV_PREFIX) && chmod 777 -R $(GCOV_PREFIX)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) CC=gcc \
		CFLAGS="${AM_CFLAGS} --coverage -fno-inline -g -O0" check

# Set QUIET=-q for non-verbose builds, otherwise set to empty.
QUIET_0 = -q
QUIET_ = $(QUIET_@AM_DEFAULT_V@)
QUIET = $(QUIET_@AM_V@)

coverage/lcov.info: gcov
if HAVE_LCOV
	-$(AM_V_at)@cp -R $(GCOV_PREFIX)/.libs $(builddir) 2> /dev/null
	$(AM_V_GEN) $(LCOV) $(QUIET)				\
		-c -d $(builddir)/.libs -o $(GCOV_PREFIX)/lcov.info
else
	@echo "================================================="
	@echo "You need lcov installed to generate coverage data"
	@echo "================================================="
	@false
endif

coverage: coverage/lcov.info
if HAVE_GENHTML
	$(AM_V_GEN) $(GENHTML) $(QUIET) $(GCOV_PREFIX)/lcov.info \
		-o $(GCOV_PREFIX)
else
	@echo "======================================================="
	@echo "You need genhtml installed to generate coverage reports"
	@echo "======================================================="
	@false
endif

clean-local:
	@rm -rf $(GCOV_PREFIX)
