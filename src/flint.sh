#!/bin/sh

if [ "x$1" = "x-ok" -a -f _.fl ] ; then
	echo "Saved as reference"
	mv _.fl _.fl.old
	exit 0
fi

if [ "x${VARNISHSRC}" = "x" ] ; then
	echo >&2 VARNISHSRC needs to point to varnish-cache sources
	exit 9
fi

flexelint \
	-D__FLEXELINT__ \
	${VARNISHSRC}/flint.lnt \
	flint.lnt \
	-zero \
	-I.. \
	-I${VARNISHSRC}/include \
	-I${VARNISHSRC}/bin/varnishd \
	$(ls *.c | grep -v .stub) \
	2>&1 | tee _.fl

if [ -f _.fl.old ] ; then
	diff -u _.fl.old _.fl
fi

if [ "x$1" = "x-ok" ] ; then
	echo "Saved as reference"
	mv _.fl _.fl.old
fi
