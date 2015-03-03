============
vmod_example
============

----------------------
Varnish Example Module
----------------------

:Date: 2015-03-03
:Version: 1.0
:Manual section: 3

SYNOPSIS
========

import example;

DESCRIPTION
===========

Example Varnish vmod demonstrating how to write an out-of-tree Varnish vmod.

Implements the traditional Hello World as a vmod.

FUNCTIONS
=========

hello
-----

Prototype
        ::

                hello(STRING S)
Return value
	STRING
Description
	Returns "Hello, " prepended to S
Example
        ::

                set resp.http.hello = example.hello("World");

INSTALLATION
============

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the ``varnishtest`` tool.

Building requires the Varnish header files and uses pkg-config to find
the necessary paths.

If you have installed Varnish to a non-standard directory, you may need to
override PKG_CONFIG_PATH so configure can find varnishapi.pc.

Usage::

 ./autogen.sh
 ./configure


Make targets:

* make - builds the vmod.
* make install - installs your vmod.
* make check - runs the unit tests in ``src/tests/*.vtc``
* make distcheck - run check and prepare a tarball of the vmod.

In your VCL you could then use this vmod along the following lines::
        
        import example;

        sub vcl_deliver {
                # This sets resp.http.hello to "Hello, World"
                set resp.http.hello = example.hello("World");
        }

COPYRIGHT
=========

See the LICENSE file for information on licensing.

* Copyright (c) 2011-2015 Varnish Software
