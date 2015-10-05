AM_CPPFLAGS = @VMOD_INCLUDES@ -Wall -Werror

vmoddir = @VMOD_DIR@
vmod_LTLIBRARIES = libvmod_named.la

libvmod_named_la_LDFLAGS = -module -export-dynamic -avoid-version -shared

libvmod_named_la_SOURCES = \
	vmod_named.c

nodist_libvmod_named_la_SOURCES = \
	vcc_if.c \
	vcc_if.h

dist_man_MANS = vmod_named.3

vmod_named.3: vmod_named.man.rst
	${RST2MAN} $< $@

vmod_named.lo vmod_named.man.rst: vcc

vcc: @VMODTOOL@ $(top_srcdir)/src/vmod_named.vcc
	@VMODTOOL@ $(top_srcdir)/src/vmod_named.vcc

VMOD_TESTS = $(top_srcdir)/src/tests/*.vtc
.PHONY: $(VMOD_TESTS) vcc

$(top_srcdir)/src/tests/*.vtc: libvmod_named.la
	@VARNISHTEST@ -Dvarnishd=@VARNISHD@ -Dvmod_topbuild=$(abs_top_builddir) $@

check: $(VMOD_TESTS)

EXTRA_DIST = \
	vmod_named.vcc \
	$(VMOD_TESTS)

CLEANFILES = \
	$(builddir)/vcc_if.c \
	$(builddir)/vcc_if.h \
	$(builddir)/vmod_named.rst \
	$(builddir)/vmod_named.man.rst \
	$(dist_man_MANS)
