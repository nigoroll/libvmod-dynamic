============
vmod-dynamic
============

.. role:: ref(emphasis)

This branch is for **Varnish-Cache after release 7.7**

Use branch `7.7`_ with Varnish-Cache 7.7.x.

See `CHANGES.rst`_ to stay informed about important changes between
versions.

.. _7.7: https://github.com/nigoroll/libvmod-dynamic/tree/7.7

.. _`CHANGES.rst`: CHANGES.rst


Description
===========

This module provides a varnish director for dynamic creation of
backends based on calls to

* the system's network address resolution service which, in turn,
  typically use information from the ``/etc/hosts`` file and the
  Domain Name Service (DNS), but can be configured to use other
  sources like LDAP (see :ref:`nsswitch.conf(5)`).

* or more advanced DNS resolution where `getdns`_ is available.

While standard varnish backends defined in VCL may also be defined in
terms of host names, changes of the name service information will only
be picked up with a VCL reload.

In contrast, for dynamic backends provided by this module,

* name resolution information will be refreshed by background threads
  after a configurable time to live (ttl) or after the ttl from DNS
  with a `getdns`_ `vmod_dynamic.resolver`.

* resolution to multiple network addresses is supported

In addition, with a `getdns`_ `vmod_dynamic.resolver`, service
discovery by DNS SRV records is possible, in which case this module
also allows to configure host names (*targets*), their ports, priority
and weight though DNS. See https://en.wikipedia.org/wiki/SRV_record
for a good basic explanation and `vmod_dynamic.director.service` for
details.

Further documentation is available in the manual page ``vmod_dynamic(3)``.

.. _getdns: https://getdnsapi.net/

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

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the ``varnishtest`` tool.

For extended resolver functionality, `getdns`_ is required both during
installation and at runtime. Before building, install `getdns`_ from
source or install developer packages, e.g.::

	apt-get install libgetdns-dev

At runtime, only the library itself is required, e.g.::

	apt-get install libgetdns1

.. getdns: https://getdnsapi.net/

Building requires the Varnish header files and uses pkg-config to find
the necessary paths.

Usage::

 ./autogen.sh
 ./configure

If you have installed Varnish to a non-standard directory, call
``autogen.sh`` and ``configure`` with ``PKG_CONFIG_PATH`` pointing to
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
* make check - runs the unit tests in ``src/tests/*.vtc``.
* make distcheck - run check and prepare a tarball of the vmod.

If you build a dist tarball, you don't need any of the autotools, only
pkg-config and Varnish. You can build the module simply by running::

 ./configure
 make

For the test suite to work, please add this line to your ``/etc/hosts``::

	127.0.0.1 www.localhost img.localhost

then run::

	make check

Also, the service tests require direct access to public DNS (for now).

Alternatively, the ``make check`` can also be skipped.

You can then proceed with the installation::

    sudo make install

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

SUPPORT
=======

.. _github.com issues: https://github.com/nigoroll/libvmod-dynamic/issues

To report bugs, use `github.com issues`_.

For enquiries about professional service and support, please contact
info@uplex.de\ .

CONTRIBUTING
============

.. _pull requests on github.com: https://github.com/nigoroll/libvmod-dynamic/pulls

To contribute to the project, please use `pull requests on github.com`_.

To support the project's development and maintenance, there are
several options:

.. _paypal: https://www.paypal.com/donate/?hosted_button_id=BTA6YE2H5VSXA

.. _github sponsor: https://github.com/sponsors/nigoroll

* Donate money through `paypal`_. If you wish to receive a commercial
  invoice, please add your details (address, email, any requirements
  on the invoice text) to the message sent with your donation.

* Become a `github sponsor`_.

* Contact info@uplex.de to receive a commercial invoice for SWIFT
  payment.

See also
========

If you want to learn more about DNS, you can start with `RFC 1034`_ and other
RFCs that updated it over time. You may also have DNS already in place, or may
be interested in setting up a name server in your infrastructure. Below is a
non-exhaustive list of tools and services, but for free software name servers
you can have a look at debianadmin_.

.. _RFC 1034: https://tools.ietf.org/html/rfc1034
.. _debianadmin: http://www.debianadmin.com/open-source-domain-name-systemdns-servers.html

DNS in the cloud (in alphabetic order):

- AWS_
- Azure_
- `Digital Ocean`_
- `Google Cloud`_
- Heroku_

.. _AWS: https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/using-instance-addressing.html
.. _Azure: https://azure.microsoft.com/en-us/documentation/articles/dns-overview/
.. _Digital Ocean: https://www.digitalocean.com/community/tutorials/how-to-set-up-a-host-name-with-digitalocean
.. _Google Cloud: https://cloud.google.com/dns/
.. _Heroku: https://devcenter.heroku.com/articles/zerigo_dns

DNS and containers (in alphabetic order):

* `DC/OS`_ (Mesos)
* `Docker Machine`_ (sort of)
* Kubernetes_

.. _DC/OS: https://docs.mesosphere.com/1.7/usage/service-discovery/mesos-dns/
.. _Docker Machine: https://www.npmjs.com/package/docker-machine-dns
.. _Kubernetes: http://kubernetes.io/docs/admin/dns/

ACKNOWLEDGEMENTS
================

We thank the various people and companies having made vmod_dynamic a
reality:

vmod_dynamic is based upon vmod_named developed and maintained from
2015 to 2017 by Dridi Boukelmoune (github @dridi) and supported by
Varnish Software.

Maintenance and improvements 2017 - 2019 were sponsored by various
unnamed UPLEX clients and authored by Geoffrey Simmons and Nils Goroll
from UPLEX.

SRV record support and getdns integration in 2019 was supported by
GOG.com

vmod_dynamic also contains contributions by: Ricardo Nabinger Sanchez,
Ryan Steinmetz
