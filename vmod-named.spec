Summary: Named VMOD for Varnish
Name: vmod-named
Version: 0.1
Release: 1%{?dist}
License: BSD
Source0: libvmod-named.tar.gz

Requires: varnish >= 4.1.0

BuildRequires: make
BuildRequires: python-docutils
BuildRequires: varnish >= 4.1.0
BuildRequires: varnish-libs-devel >= 4.1.0


%description
A VMOD to create named director, that is to say relying on DNS to dynamically
create backends.


%prep
%setup -qn libvmod-named-trunk


%build
%configure --prefix=/usr/
%{__make} %{?_smp_mflags}


%install
[ %{buildroot} != "/" ] && %{__rm} -rf %{buildroot}
%{__make} install DESTDIR=%{buildroot}
mv %{buildroot}/usr/share/doc/lib%{name} %{buildroot}/usr/share/doc/%{name}


%check
%{__make} %{?_smp_mflags} check


%clean
[ %{buildroot} != "/" ] && %{__rm} -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_libdir}/varnis*/vmods/
%doc /usr/share/doc/%{name}/*
%{_mandir}/man?/*

%changelog
* Wed Sep 30 2015 Dridi Boukelmoune <dridi.boukelmoune[AT]gmail.com> - 0.1-1
- Initial version.
