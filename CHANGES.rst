vmod_dynamic CHANGELOG
======================

This file contains a summary of relevant changes to this vmod after
version 2.8.0.

vmod_dynamic NEXT
=================

.. UP TO: eefe4a5f10d984f3f98df90b70edeffbb1209644

7.4 branch
----------

.. _109: https://github.com/nigoroll/libvmod-dynamic/issues/109

* Fix handling of backends which are in the process of being created
  (`109`_)

.. _107: https://github.com/nigoroll/libvmod-dynamic/issues/107
.. _VC#4037: https://github.com/varnishcache/varnish-cache/pull/4037

* Work around wrong event order in Varnish-Cache (`VC#4037`_, `107`_).

.. _105: https://github.com/nigoroll/libvmod-dynamic/issues/105

* Fixed race between lookup thread creation and cold events (`105`_)

* Thanks to the move to reference counting, the service update
  interval is now independent of the dynamic backend lifetime.

.. _102: https://github.com/nigoroll/libvmod-dynamic/issues/102

* Improved support for layered director configurations and fixed
  special cases (`102`_ and bugs without an issue number)

.. _101: https://github.com/nigoroll/libvmod-dynamic/issues/101

* Fixed Hang & child CLI timeout (`101`_)

.. _76: https://github.com/nigoroll/libvmod-dynamic/pull/76

* An ``authority`` argument has been added to the ``.backend()``
  method and the ``dynamic.director()`` constructor as an object-wide
  default to allow control over the Authority TLV sent with PROXY
  requests to a via backend, which usually ends up as SNI in a backend
  TLS connection (based upon `76`_).

* The general log format has been adjusted to that of ``Timestamp``
  log records in that the colon has been removed from the
  ``vmod-dynamic:`` prefix. All log records now start with
  ``vmod-dynamic``.

* When there is no healthy backend for a domain, the ``.backend()``
  method now returns a (possibly) unhealthy domain director rather
  than none at all.

  This should help in situations where new backends have been added
  and a probe has not yet returned.

* Domains and services are now organized using a red/black tree which
  improves lookup times in particular with many domains and services
  per director (from *O(n)* to *O(log n)*).

* Domain backends (those for IP addresses which a domain resolves to)
  are now created while other requests continue to be served. This
  should improve performance, lower latencies and fix a deadlock with
  the new ``backend.list`` callback.

* Expiry of domains and services after ``domain_usage_timeout`` has
  been refactored to improve performance and scalability with many
  domains / services per director.

* A ``backend.list`` callback has been implemented to query details
  about dynamic domains and their active backends.

7.3 branch
----------

* The new constructor parameter ``keep`` specifies for how many
  updates to keep no longer referenced backends configured.

  The main use case is to preserve backend statistics when name
  resolution returns varying a subset of ip addresses from a larger
  set.

* Internal handling of backends has been substantially refactored,
  with the ultimate goal to use the updated varnish API for reference
  counting of backends.

  This should eleminate any use-after-free issues.

* vmod_dynamic now supports *via* backends, which, besides other use
  cases, enables dynamic https backends with a TLS *onloader*
  accepting the connection parameters from a PROXY protocol preamble.

  For example, with ``haproxy`` and a configuration like this::

    listen sslon
      mode    tcp
      maxconn 1000
      bind    /path/to/sslon accept-proxy mode 777
      stick-table type ip size 100
      stick   on dst
      server  s00 0.0.0.0:443 ssl ca-file /etc/ssl/certs/ca-bundle.crt alpn http/1.1 sni fc_pp_authority
      server  s01 0.0.0.0:443 ssl ca-file /etc/ssl/certs/ca-bundle.crt alpn http/1.1 sni fc_pp_authority
      server  s02 0.0.0.0:443 ssl ca-file /etc/ssl/certs/ca-bundle.crt alpn http/1.1 sni fc_pp_authority
      # ...
      # A higher number of servers improves TLS session caching

  dynamic tls backends can be used from VCL like so::

    backend sslon {
      .path = "/path/to/sslon";
    }

    sub vcl_init {
      new https = dynamic.director(via = sslon, port = 443);
    }

    sub vcl_backend_request {
      set bereq.backend = https.backend();
    }

  The ``haproxy`` configuration defines a frontend on a Unix Domain
  Socket (UDS) with several backends to make TLS connections. The
  certificates presented by the servers are validated against the
  given CA bundle.  The http/1.1 ALPN is selected and the SNI
  authority is also taken from the PROXY preamble.

  The VCL configuration defines a proxy backend named ``sslon`` on the
  UDS provided by ``haproxy``, which is then configured to be used by
  the dynamic director named ``https``. If that is used, ``haproxy``
  is instructed to make a TLS connection. By default, if no host
  argument is given to the ``.backend()`` method, the DNS name to
  connect to and the SNI authority are taken from the ``Host`` header.

* Previously, domain resolution always started when the VCL became
  warm.

  Now it also starts earlier when a dynamic backend is requested in
  ``vcl_init {}``.

  This was a requirement for the next change:

* Dynamic backends can now safely be layered unter other directors, such as::

    sub vcl_init {
      new d1 = dynamic.director();
      new rr = directors.round_robin();
      rr.add_backend(d1.backend("foo.com"));
    }

  Previously, this usage pattern could trigger an assertion.

* A health state query now also waits for initial DNS resolution,
  as using a backend does.

  This is particularly helpful with director layering, as most
  directors only consider healthy backends and dynamic backends only
  become healthy once they could resolve to at least one address.
