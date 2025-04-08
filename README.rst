Use branch `7.7`_ with Varnish-Cache 7.7.x.

============
vmod_dynamic
============

-------------------------------
Varnish dynamic backends module
-------------------------------

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
  with a `getdns`_ `dynamic.resolver()`_.

* resolution to multiple network addresses is supported

In addition, with a `getdns`_ `dynamic.resolver()`_, service
discovery by DNS SRV records is possible, in which case this module
also allows to configure host names (*targets*), their ports, priority
and weight though DNS. See https://en.wikipedia.org/wiki/SRV_record
for a good basic explanation and `xdirector.service()`_ for
details.

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

SEE ALSO
========

* :ref:`vcl(7)`
* :ref:`vsl(7)`
* :ref:`vsl-query(7)`
* :ref:`varnish-cli(7)`
* :ref:`varnish-counters(7)`
* :ref:`varnishstat(1)`
* :ref:`getaddrinfo(3)`
* :ref:`nscd(8)`
* :ref:`nsswitch.conf(5)`

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

Maintenance and improvements 2017 - 2019:

Generally sponsored by Spring Media and various unnamed UPLEX clients.

SRV record support and getdns integration in 2019 was supported by
GOG.com

Code was written mostly by Geoffrey Simmons and Nils Goroll from UPLEX
with additional contributions by: Ricardo Nabinger Sanchez and
Ryan Steinmetz.

Thank you to all!

COPYRIGHT
=========

::

  Copyright (c) 2015-2016 Dridi Boukelmoune
  Copyright 2017-2023 UPLEX - Nils Goroll Systemoptimierung
 
  Authors: Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
 	   Nils Goroll <nils.goroll@uplex.de>
 
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
 
  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
  SUCH DAMAGE.
