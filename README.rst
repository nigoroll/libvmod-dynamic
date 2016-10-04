============
vmod-dynamic
============

Description
===========

The purpose of this module is to provide a dynamic director similar to
the DNS director from Varnish 3. It also was previously known as
`vmod-named`. This is not a drop-in replacement for the DNS director,
because in Varnish 3 the director had two modes of execution that
aren't compatible with changes in the backend and director subsystems
introduced by Varnish 4.0.

Instead a dynamic director relies on dynamic backends, supports white-listing
and even probes. However, just like the DNS director from Varnish 3 it has
limited capabilities because it relies on the system's resolver. It builds
against Varnish 4.1.2 and later versions.

Further documentation is available in the manual page ``vmod_dynamic(3)``.

Installation
============

The module requires the GNU Build System, you may follow these steps::

    ./autogen.sh
    ./configure
    make

For the test suite to work, please add this line to your ``/etc/hosts``::

	127.0.0.1 www.localhost img.localhost

then run::

	make check

Alternatively, the ``make check`` can also be skipped.

You can then proceed with the installation::

    sudo make install

Instead of directly installing the package you can build an RPM instead::

    make dist
    rpmbuild -tb *.tar.gz

If you need to build an RPM for a different platform you may use ``mock(1)``::

    make dist
    mock --buildsrpm --resultdir . --sources . --spec vmod-querystring.spec
    mock --rebuild   --resultdir . *.src.rpm

If your Varnish installation did not use the default ``/usr`` prefix, you need
this in your environment before running ``./autogen.sh``::

    export PKG_CONFIG_PATH=/path/to/lib/pkgconfig

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
