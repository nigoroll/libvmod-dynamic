#!/bin/sh

warn() {
	echo "WARNING: $@" 1>&2
}

case `uname -s` in
Darwin)
	LIBTOOLIZE=glibtoolize
	;;
FreeBSD)
	LIBTOOLIZE=libtoolize
	;;
Linux)
	LIBTOOLIZE=libtoolize
	;;
SunOS)
	LIBTOOLIZE=libtoolize
	;;
*)
	warn "unrecognized platform:" `uname -s`
	LIBTOOLIZE=libtoolize
esac

automake_version=`automake --version | tr ' ' '\n' | egrep '^[0-9]\.[0-9a-z.-]+'`
if [ -z "$automake_version" ] ; then
	warn "unable to determine automake version"
else
	case $automake_version in
		0.*|1.[0-8]|1.[0-8][.-]*)
			warn "automake ($automake_version) detected; 1.9 or newer recommended"
			;;
		*)
			;;
	esac
fi

set -ex

# check for varnishapi.m4 in custom paths
dataroot=$(pkg-config --variable=datarootdir varnishapi)
aclocal -I m4 -I ${dataroot}/aclocal
$LIBTOOLIZE --copy --force
autoheader
automake --add-missing --copy --foreign
autoconf
