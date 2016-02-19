%global vmod    named
%global vmoddir %{_libdir}/varnish/vmods

Name:           vmod-%{vmod}
Version:        0.2
Release:        1%{?dist}
Group:          System Environment/Libraries
Summary:        DNS director for Varnish Cache
URL:            https://www.varnish-cache.org/vmod/%{vmod}
License:        BSD

Source:         lib%{name}-%{version}.tar.gz

BuildRequires:  python
BuildRequires:  varnish >= 4.1
BuildRequires:  varnish-libs-devel >= 4.1

Requires:       varnish >= 4.1

%description
A VMOD to create named director, that is to say relying on DNS to dynamically
create backends.


%prep
%setup -qn lib%{name}-%{version}


%build
%configure --with-rst2man=true
make %{?_smp_mflags}


%install
%make_install
rm %{buildroot}%{vmoddir}/libvmod_%{vmod}.la


%check
make %{?_smp_mflags} check


%files
%{vmoddir}/libvmod_%{vmod}.so
%{_mandir}/man?/*
%{_docdir}/*


%changelog
* Fri Feb 19 2016 Dridi Boukelmoune <dridi.boukelmoune[AT]gmail.com> - 0.3-1
- RPM spec cleanup.

* Fri Nov 27 2015 Dridi Boukelmoune <dridi.boukelmoune[AT]gmail.com> - 0.2-1
- Implementation is closer to Varnish 3's DNS director.

* Wed Sep 30 2015 Dridi Boukelmoune <dridi.boukelmoune[AT]gmail.com> - 0.1-1
- Initial version.
