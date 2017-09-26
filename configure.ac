AC_PREREQ([2.68])
AC_INIT([libvmod-dynamic], [0.2], [], [vmod-dynamic])
AC_COPYRIGHT([Copyright (c) 2015-2016 Dridi Boukelmoune])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/vmod_dynamic.vcc])
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE([1.11 -Wall -Werror foreign parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_AR

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

AC_ARG_WITH([rst2man],
	AS_HELP_STRING(
		[--with-rst2man=PATH],
		[Location of rst2man (auto)]),
	[RST2MAN="$withval"],
	AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], []))

m4_ifndef([VARNISH_PREREQ], AC_MSG_ERROR([Need varnish.m4 -- see README.rst]))

VARNISH_PREREQ([4.1.2])
VARNISH_VMODS([dynamic])

PKG_CHECK_VAR([LIBVARNISHAPI_LIBDIR], [varnishapi], [libdir])
AC_SUBST([VARNISH_LIBRARY_PATH],
	[$LIBVARNISHAPI_LIBDIR:$LIBVARNISHAPI_LIBDIR/varnish])

AC_SUBST([VTC_TESTS], "$(cd $srcdir/src && echo tests/*.vtc)")

AS_VERSION_COMPARE([$VARNISH_VERSION], [5.0], [
	AC_DEFINE([HAVE_VCL_EVENT_USE], [1], [Define if USE events are sent.])])

AS_VERSION_COMPARE([$VARNISH_VERSION], [5.1], [], [
	AC_DEFINE([HAVE_BACKEND_PROXY], [1], [Define if backends support PROXY.])], [
	AC_DEFINE([HAVE_BACKEND_PROXY], [1], [Define if backends support PROXY.])])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
