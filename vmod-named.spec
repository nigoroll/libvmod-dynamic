Summary: DNS director for Varnish 4.1
Name: vmod-named
Version: 0.2
Release: 1%{?dist}
License: BSD
Source0: lib%{name}-%{version}.tar.gz

Requires: varnish >= 4.1.0

BuildRequires: make
BuildRequires: python-docutils
BuildRequires: varnish >= 4.1.0
BuildRequires: varnish-libs-devel >= 4.1.0


%description
A VMOD to create named director, that is to say relying on DNS to dynamically
create backends.


%prep
%setup -qn lib%{name}-%{version}


%build
%configure --prefix=/usr/
%{__make} %{?_smp_mflags}


%install
%{__make} install DESTDIR=%{buildroot}
mv %{buildroot}/usr/share/doc/lib%{name} %{buildroot}/usr/share/doc/%{name}

rm %{buildroot}%{_libdir}/varnish*/vmods/*.la


%check
%{__make} %{?_smp_mflags} check


%files
%defattr(-,root,root,-)
%{_libdir}/varnish*/vmods/
%doc /usr/share/doc/%{name}/*
%doc %{_mandir}/man?/*

%changelog
* Fri Nov 27 2015 Dridi Boukelmoune <dridi.boukelmoune[AT]gmail.com> - 0.2-1
- Implementation is closer to Varnish 3's DNS director.

* Wed Sep 30 2015 Dridi Boukelmoune <dridi.boukelmoune[AT]gmail.com> - 0.1-1
- Initial version.
