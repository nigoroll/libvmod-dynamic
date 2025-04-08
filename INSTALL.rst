============
vmod_dynamic
============

-------------------------
Installation Instructions
-------------------------

Supported Operating Systems
===========================

We encourage the use of open source operating systems and primarily
support Linux and FreeBSD / OpenBSD.

This vmod should also work on any other sane UNIX-ish platform like
the Solaris Descendents and MacOS.

We specifically do not support any Windows based environments, also
not Docker on Windows. Feel free to use the VMOD, but do not expect us
to support you, unless you are willing to put substantial amounts of
money into a sponsorship.

Installation
============

.. _`getdns`: https://getdnsapi.net/

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the ``varnishtest`` tool.

For extended resolver functionality, `getdns`_ is required both during
installation and at runtime. Before building, install `getdns`_ from
source or install developer packages, e.g.::

    apt-get install libgetdns-dev

At runtime, only the library itself is required, e.g.::

    apt-get install libgetdns1

Building requires the Varnish header files and uses pkg-config to find
the necessary paths.

Usage::

 ./bootstrap

If you have installed Varnish to a non-standard directory, call
``bootstrap`` with ``PKG_CONFIG_PATH`` pointing to
the appropriate path. For instance, when varnishd configure was called
with ``--prefix=$PREFIX``, use

::

 export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
 export ACLOCAL_PATH=${PREFIX}/share/aclocal

The module will inherit its prefix from Varnish, unless you specify a
different ``--prefix`` when running the ``configure`` script for this
module.

Make targets:

* make - builds the vmod.
* make install - installs your vmod.
* make check - runs the unit tests in ``src/vtc/*.vtc``.
* make distcheck - run check and prepare a tarball of the vmod.

If you build a dist tarball, you don't need any of the autotools, only
pkg-config and Varnish. You can build the module simply by running::

 ./configure
 make

Installation directories
------------------------

By default, the vmod ``configure`` script installs the built vmod in the
directory relevant to the prefix. The vmod installation directory can be
overridden by passing the ``vmoddir`` variable to ``make install``.

FreeBSD
-------

FreeBSD users may install from either the ports tree or via packages:

* via the Ports Tree

  ``cd /usr/ports/www/varnish-libvmod-dynamic/ && make install clean``

* via the Package

  ``pkg install varnish-libvmod-dynamic``

RPMs
----

Binary, debuginfo and source RPMs for VMOD dynamic are available at::

    https://pkg.uplex.de/

The packages are built for Enterprise Linux 7 (el7), and hence will
run on compatible distros (such as RHEL7, Fedora, CentOS 7 and Amazon
Linux).

To set up your YUM repository for the RPMs::

    yum-config-manager --add-repo https://pkg.uplex.de/rpm/7/uplex-varnish/x86_64/

The RPMs are compatible with Varnish versions 6.3.2 and 6.4.0. They
also require the ``getdns`` library, as discussed above. The library
is not necessarily available in the distributions' standard
repositories, but can be installed from EPEL7::

    yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

If you have problems or questions concerning the RPMs, post an issue
to one of the source repository web sites, or contact
<varnish-support@uplex.de>.
