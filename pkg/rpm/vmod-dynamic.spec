# -D MUST pass in _version and _release, and SHOULD -pass in dist.

%global vmod    dynamic
%global vmoddir %{_libdir}/varnish/vmods

Name:           vmod-%{vmod}
Version:        %{_version}
Release:        %{_release}%{?dist}
Group:          System Environment/Libraries
Summary:        DNS director for Varnish Cache
URL:            https://github.com/nigoroll/libvmod-dynamic
License:        BSD

Source:         %{name}-%{version}.tar.gz

BuildRequires:  varnish-devel == 6.3.2
BuildRequires:  pkgconfig
BuildRequires:  make
BuildRequires:  gcc
BuildRequires:  python-docutils >= 0.6

# varnish from varnish63 at packagecloud
# Require getdns, so that resolver objects may be used.
Requires:       varnish == 6.3.2
Requires:       getdns

Provides: %{name}, %{name}-debuginfo

%description
A VMOD to create dynamic director, that is to say relying on DNS to dynamically
create backends.


%prep
%setup -qn %{name}-%{version}


%build
%configure --with-rst2man=true
make %{?_smp_mflags}


%install
%make_install
rm %{buildroot}%{vmoddir}/libvmod_%{vmod}.la

# Only use the version-specific docdir created by %doc below
rm -rf %{buildroot}%{_docdir}

%check
make %{?_smp_mflags} check


%files
%{vmoddir}/libvmod_%{vmod}.so
%{_mandir}/man?/*
%doc README.rst COPYING LICENSE


%changelog
* Thu Jun 25 2020 Geoff Simmons <geoff[AT]uplex.de> - %{_version}-%{_release}
- dynamic director can be layered with other directors.
- dynamic.backend() may be called in vcl_init.

* Fri Jun 19 2020 Geoff Simmons <geoff[AT]uplex.de> - 2.1.0-1
- Require getdns.
- Compatibility with Varnish 6.3.2.

* Mon Apr 02 2018 Geoff Simmons <geoff[AT]uplex.de> - 0.4-1
- Compatibility with Varnish 6.0.0.

* Fri Nov 24 2017 Geoff Simmons <geoff[AT]uplex.de> - 0.3-1
- Rework RPM packaging for publication at packagecloud.
- Previous changelog entry is incorrect, *this* is version 0.3.

* Fri Feb 19 2016 Dridi Boukelmoune <dridi.boukelmoune[AT]gmail.com> - 0.3-1
- RPM spec cleanup.

* Fri Nov 27 2015 Dridi Boukelmoune <dridi.boukelmoune[AT]gmail.com> - 0.2-1
- Implementation is closer to Varnish 3's DNS director.

* Wed Sep 30 2015 Dridi Boukelmoune <dridi.boukelmoune[AT]gmail.com> - 0.1-1
- Initial version.
