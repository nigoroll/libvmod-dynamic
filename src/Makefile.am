AM_CPPFLAGS = @VMOD_INCLUDES@
AM_CFLAGS = -Wall -Werror -Wextra

# VMOD library

vmoddir = @VMOD_DIR@
vmod_LTLIBRARIES = libvmod_dynamic.la

VCC_FILES = \
	vcc_if.c \
	vcc_if.h

DOC_FILES = \
	vmod_dynamic.rst \
	vmod_dynamic.man.rst

libvmod_dynamic_la_LDFLAGS = \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared

libvmod_dynamic_la_SOURCES = \
	vmod_dynamic.h \
	vmod_dynamic.c

nodist_libvmod_dynamic_la_SOURCES = \
	$(VCC_FILES)

$(srcdir)/vmod_dynamic.c: $(VCC_FILES)

$(VCC_FILES) $(DOC_FILES): .vcc

.vcc: vmod_dynamic.vcc
	@echo vmodtool: @VMODTOOL@ $<
	@@VMODTOOL@ $<
	@touch $@

# Documentation

dist_man_MANS = vmod_dynamic.3

vmod_dynamic.3: vmod_dynamic.man.rst
	${RST2MAN} $< $@

# Test suite

VMOD_FILE="$(abs_builddir)/.libs/libvmod_dynamic.so"

VTC_LOG_COMPILER = \
	env PATH="@TEST_PATH@" \
	varnishtest -v \
	-Dvmod_dynamic="dynamic from \"$(VMOD_FILE)\""

TEST_EXTENSIONS = .vtc

TESTS = @VTC_TESTS@

EXTRA_DIST = \
	vmod_dynamic.vcc \
	@VTC_TESTS@

# misc

CLEANFILES = \
	$(VCC_FILES) \
	$(DOC_FILES) \
	$(dist_man_MANS) \
	.vcc
