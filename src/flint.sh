#!/bin/sh

if [ "x$1" = "x-ok" -a -f _.fl ] ; then
	echo "Saved as reference"
	mv _.fl _.fl.old
	exit 0
fi

if [ "x${VINYLSRC}" = "x" ] ; then
	echo >&2 VINYLSRC needs to point to vinyl-cache sources
	exit 9
fi

flexelint \
	-D__FLEXELINT__ \
	${VINYLSRC}/flint.lnt \
	flint.lnt \
	-zero \
	-I.. \
	-I${VINYLSRC}/include \
	-I${VINYLSRC}/bin/vinyld \
	$(ls *.c | grep -v .stub) \
	2>&1 | tee _.fl

if [ -f _.fl.old ] ; then
	diff -u _.fl.old _.fl
fi

if [ "x$1" = "x-ok" ] ; then
	echo "Saved as reference"
	mv _.fl _.fl.old
fi
