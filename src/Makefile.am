AM_CFLAGS = $(VARNISHAPI_CFLAGS) -Wall -Werror
AM_LDFLAGS = $(VARNISHAPI_LIBS) $(VMOD_LDFLAGS)

vmod_LTLIBRARIES = libvmod_dynamic.la

libvmod_dynamic_la_SOURCES = \
	vmod_dynamic.h \
	vmod_dynamic.c

nodist_libvmod_dynamic_la_SOURCES = \
	vcc_dynamic_if.c \
	vcc_dynamic_if.h

dist_man_MANS = vmod_dynamic.3

pdf-local: vmod_dynamic.pdf

.rst.pdf:
	rst2pdf $< $@

@BUILD_VMOD_DYNAMIC@

AM_TESTS_ENVIRONMENT = \
	PATH="$(VMOD_TEST_PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = -Dvmod_dynamic="$(VMOD_DYNAMIC)"

TESTS = @VTC_TESTS@

EXTRA_DIST = \
	vmod_dynamic.vcc \
	@VTC_TESTS@
