vmod_dynamic CHANGELOG
======================

This file contains a summary of relevant changes to this vmod after
version 2.8.0.

vmod_dynamic NEXT
=================

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
