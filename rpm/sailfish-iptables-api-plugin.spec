Name: sailfish-iptables-api-plugin
Version: 0.0.1
Release: 0
Summary: Sailfish Connman iptables api plugin
Group: Development/Libraries
License: GPLv2
URL: https://github.com/LaakkonenJussi/sailfish-connman-plugin-iptables-api
Source: %{name}-%{version}.tar.bz2
Requires: iptables
Requires: connman >= 1.31+git44
BuildRequires: iptables-devel
BuildRequires: connman-devel >= 1.31+git44
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
This package contains the Sailfish Connman iptables API plugin library.

%prep
%setup -q -n %{name}-%{version}

%build
make %{?jobs:-j%jobs} release

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/%{_libdir}/connman/plugins
%preun

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/connman/plugins/sailfish-iptables-api-plugin.so
