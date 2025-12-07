AC_PREREQ([2.68])
AC_INIT([libvmod-dynamic], [trunk], [varnish-support@uplex.de], [vmod-dynamic])
AC_COPYRIGHT([Copyright 2024 UPLEX - Nils Goroll Systemoptimierung])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.11 -Wall -Werror foreign parallel-tests])
AM_SILENT_RULES([yes])

AC_ARG_VAR([RST2MAN], [the program to build manuals from reStructuredText])
AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py])

VARNISH_PREREQ([7.5.0])
VARNISH_VMODS([dynamic])

AM_PROG_AR

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

AC_CHECK_HEADERS([stdatomic.h])

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
		echo vtc/*.vtc vtc/{resolver,service}/*.vtc)")],
	[AC_MSG_WARN([extended resolver functions will not be available])
	 AM_CONDITIONAL([HAVE_GETDNS], [false])
	 AC_SUBST([VTC_TESTS], "$(cd $srcdir/src && echo vtc/*.vtc vtc/nogetdns/*.vtc)")])
  ],
  [AS_MESSAGE([extended resolver functions will not be available])
   AM_CONDITIONAL([HAVE_GETDNS], [false])
   AC_SUBST([VTC_TESTS], "$(cd $srcdir/src && echo vtc/*.vtc vtc/nogetdns/*.vtc)")
  ])

AC_CHECK_HEADERS([cache/cache.h], [],
    [AC_MSG_ERROR([Missing \$VARNISHSRC development files.])],
       [[#include <cache/cache.h>]])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_CHECK_PROG([HAVE_GIT], [git], [yes], [no])
if test "x$HAVE_GIT" = "xyes"; then
	if git rev-parse --git-dir >/dev/null 2>&1; then
		HAVE_GIT_REPO=yes
	else
		HAVE_GIT_REPO=no
	fi
else
	HAVE_GIT_REPO=no
fi
AM_CONDITIONAL([HAVE_VCS_VMOD_VERSION], [test -f "src/vmod_vcs_version.txt" || test "x$HAVE_GIT_REPO" = "xyes"])
if test "x$HAVE_GIT_REPO" != "xyes" && test ! -f "src/vmod_vcs_version.txt"; then
   AC_MSG_WARN([Building without version control metadata - vmod_vcs_version.txt will be unavailable])
fi

AC_OUTPUT

AS_ECHO("
	==== $PACKAGE_STRING ====

	varnish:      $VARNISH_VERSION
	prefix:       $prefix
	vmoddir:      $vmoddir
	vcldir:       $vcldir
	pkgvcldir:    $pkgvcldir

	compiler:     $CC
	cflags:       $CFLAGS
	ldflags:      $LDFLAGS
")
