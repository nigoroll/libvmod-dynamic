AM_CPPFLAGS = @VMOD_INCLUDES@
AM_CFLAGS = -Wall -Werror -Wextra

# VMOD library

vmoddir = @VMOD_DIR@
vmod_LTLIBRARIES = libvmod_named.la

VCC_FILES = \
	vcc_if.c \
	vcc_if.h

DOC_FILES = \
	vmod_named.rst \
	vmod_named.man.rst

libvmod_named_la_LDFLAGS = \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared

libvmod_named_la_SOURCES = \
	vmod_named.c

nodist_libvmod_named_la_SOURCES = \
	$(VCC_FILES)

$(srcdir)/vmod_named.c: $(VCC_FILES)

$(VCC_FILES) $(DOC_FILES): .vcc

.vcc: vmod_named.vcc
	@echo vmodtool: @VMODTOOL@ $<
	@@VMODTOOL@ $<
	@touch $@

# Documentation

dist_man_MANS = vmod_named.3

vmod_named.3: vmod_named.man.rst
	${RST2MAN} $< $@

# Test suite


VTC_LOG_COMPILER = \
	env PATH="@TEST_PATH@" \
	varnishtest -v \
	-Dvmod_topbuild=$(abs_top_builddir)

TEST_EXTENSIONS = .vtc

TESTS = @VTC_TESTS@

EXTRA_DIST = \
	vmod_named.vcc \
	@VTC_TESTS@

# misc

CLEANFILES = \
	$(VCC_FILES) \
	$(DOC_FILES) \
	$(dist_man_MANS) \
	.vcc
