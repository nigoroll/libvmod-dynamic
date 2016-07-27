==========
vmod-named
==========

Description
===========

The purpose of this module is to provide a named director similar to the DNS
director from Varnish 3. This is not a drop-in replacement, because in Varnish
3 the director had two modes of execution that aren't compatible with changes
in the backend and director subsystems introduced by Varnish 4.0.

Instead a named director relies on dynamic backends, supports white-listing
and even probes. However, just like the DNS director from Varnish 3 it has
limited capabilities because it relies on the system's resolver. It builds
against Varnish 4.1.2 and later versions.

Further documentation is available in the manual page ``vmod_named(3)``.

Installation
============

The module requires the GNU Build System, you may follow these steps::

    ./autogen.sh
    ./configure
    make

The test suite may not currently run without global (but minor) changes to
your system. You can skip the test suite or run it with::

    make check

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

If you want to learn more about DNS, you can start with `RFC 1034`__ and other
RFCs that updated it over time. You may also have DNS already in place, or may
be interested in setting up a name server in your infrastructure. Below is a
non-exhaustive list of tools and services, but for free software name servers
you can have a look at debianadmin__.

__ https://tools.ietf.org/html/rfc1034
__ http://www.debianadmin.com/open-source-domain-name-systemdns-servers.html

DNS in the cloud (in alphabetic order):

* AWS__
* Azure__
* `Digital Ocean`__
* `Google Cloud`__
* Heroku__

__ https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/using-instance-addressing.html
__ https://azure.microsoft.com/en-us/documentation/articles/dns-overview/
__ https://www.digitalocean.com/community/tutorials/how-to-set-up-a-host-name-with-digitalocean
__ https://cloud.google.com/dns/
__ https://devcenter.heroku.com/articles/zerigo_dns

DNS and containers (in alphabetic order):

* `DC/OS (Mesos)`__
* `Docker Machine` (sort of)
* Kubernetes__

__ https://docs.mesosphere.com/1.7/usage/service-discovery/mesos-dns/
__ https://www.npmjs.com/package/docker-machine-dns
__ http://kubernetes.io/docs/admin/dns/
