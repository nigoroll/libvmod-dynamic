AC_PREREQ([2.68])
AC_INIT([libvmod-dynamic], [trunk], [varnish-support@uplex.de], [vmod-dynamic])
AC_COPYRIGHT([Copyright 2019 UPLEX - Nils Goroll Systemoptimierung])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/vmod_dynamic.vcc])
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE([1.11 -Wall -Werror foreign parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_AR

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

AC_CHECK_HEADERS([stdatomic.h])

AC_ARG_WITH([rst2man],
	AS_HELP_STRING(
		[--with-rst2man=PATH],
		[Location of rst2man (auto)]),
	[RST2MAN="$withval"],
	[AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], [])])

m4_ifndef([VARNISH_PREREQ], AC_MSG_ERROR([Need varnish.m4 -- see README.rst]))

VARNISH_PREREQ([7.2.0])
VARNISH_VMODS([dynamic])

PKG_CHECK_VAR([LIBVARNISHAPI_LIBDIR], [varnishapi], [libdir])
AC_SUBST([VARNISH_LIBRARY_PATH],
	[$LIBVARNISHAPI_LIBDIR:$LIBVARNISHAPI_LIBDIR/varnish])

AC_ARG_WITH([getdns],
	[AS_HELP_STRING([--with-getdns],
         [use getdns for service discovery by SRV [default check pkg-config]])],
        [],
        [with_getdns=yes])

GETDNS=
AS_IF([test "x$with_getdns" != xno],
  [PKG_CHECK_MODULES([GETDNS], [getdns],
	[AC_DEFINE([HAVE_GETDNS], [1], [Define if getdns is available.])
	 AM_CONDITIONAL([HAVE_GETDNS], [true])
	 AC_SUBST([VTC_TESTS], "$(cd $srcdir/src &&
		echo tests/*.vtc tests/{resolver,service}/*.vtc)")],
	[AC_MSG_WARN([extended resolver functions will not be available])
	 AM_CONDITIONAL([HAVE_GETDNS], [false])
	 AC_SUBST([VTC_TESTS], "$(cd $srcdir/src && echo tests/*.vtc)")])
  ],
  [AS_MESSAGE([extended resolver functions will not be available])
   AM_CONDITIONAL([HAVE_GETDNS], [false])
   AC_SUBST([VTC_TESTS], "$(cd $srcdir/src && echo tests/*.vtc)")
  ])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
