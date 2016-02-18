AC_PREREQ(2.59)
AC_COPYRIGHT([Copyright (c) 2015-2016 Dridi Boukelmoune])
AC_INIT([libvmod-named], [0.2])
AC_CONFIG_MACRO_DIR([m4])
m4_ifndef([VARNISH_VMOD_INCLUDES], AC_MSG_ERROR([Need varnish.m4 -- see README.rst]))
AC_CONFIG_SRCDIR(src/vmod_named.vcc)
AM_CONFIG_HEADER(config.h)

AC_CANONICAL_SYSTEM
AC_LANG(C)

AM_INIT_AUTOMAKE([foreign])

AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_CC_STDC
if test "x$ac_cv_prog_cc_c99" = xno; then
	AC_MSG_ERROR([Could not find a C99 compatible compiler])
fi
AC_PROG_CPP

AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET

# Check for rst utilities
AC_ARG_WITH([rst2man],
	AS_HELP_STRING(
		[--with-rst2man=PATH],
		[Location of rst2man (auto)]),
	[RST2MAN="$withval"],
	AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], [no]))
if test "$RST2MAN" = "no"
then
	AC_MSG_ERROR(
		[rst2man is needed to build the manual. To proceed without, specify --with-rst2man=true.])
fi

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/stdlib.h])

PKG_CHECK_MODULES([libvarnishapi], [varnishapi])
PKG_CHECK_VAR([LIBVARNISHAPI_PREFIX], [varnishapi], [prefix])
PKG_CHECK_VAR([LIBVARNISHAPI_DATAROOTDIR], [varnishapi], [datarootdir])
PKG_CHECK_VAR([LIBVARNISHAPI_BINDIR], [varnishapi], [bindir])
PKG_CHECK_VAR([LIBVARNISHAPI_SBINDIR], [varnishapi], [sbindir])
AC_SUBST([LIBVARNISHAPI_DATAROOTDIR])

# Varnish include files tree
VARNISH_VMOD_INCLUDES
VARNISH_VMOD_DIR
VARNISH_VMODTOOL

# inherit the prefix from Varnish.
# acessing ac_ variable because AC_PREFIX_DEFAULT acts too early
ac_default_prefix=$LIBVARNISHAPI_PREFIX

AC_SUBST([TEST_PATH], [$LIBVARNISHAPI_SBINDIR:$LIBVARNISHAPI_BINDIR:$PATH])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
