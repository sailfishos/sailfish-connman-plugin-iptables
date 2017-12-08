Name: sailfish-connman-iptables-plugin
Version: 0.0.1
Release: 2
Summary: Sailfish Connman iptables management plugin
Group: Development/Libraries
License: GPLv2
URL: https://github.com/sailfishos/sailfish-connman-plugin-iptables
Source: %{name}-%{version}.tar.bz2
Requires: iptables
Requires: connman >= 1.31+git50.4
Requires: glib2 >= 2.28
Requires: dbus >= 1.4
BuildRequires: iptables-devel
BuildRequires: connman-devel >= 1.31+git50.4
BuildRequires: pkgconfig(glib-2.0) >= 2.28
BuildRequires: pkgconfig(dbus-1) >= 1.4
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
This package contains the Sailfish Connman plugin for iptables management.

%package unit
Summary:    Unit tests for Sailfish Connman iptables management plugin
Group:      Development/Tools
Requires:   %{name} = %{version}
Requires:   glib2-devel >= 2.28
Requires:   bash
BuildRequires: pkgconfig(glib-2.0) >= 2.28
BuildRequires: pkgconfig(dbus-1) >= 1.4

%description unit
This package contains the unit tests and unit test runner script for Sailfish Connman iptables management plugin. 

%package test
Summary:    Test Script for Sailfish Connman iptables management plugin
Group:      Development/Tools
Requires:   %{name} = %{version}
Requires:   connman >= 1.31+git50.4
Requires:   bash
Requires:   dbus >= 1.4
Requires:   iptables

%description test
This package contains the end-to-end testing script for Sailfish Connman iptables management plugin. Testing script requires to be run as root or the user has to have privileges to use iptables commands. The testing script saves iptables filter table to a temporary file, executes tests on clean filter table and restores the previous state of iptables filter table. Tests are conducted using the sailfish iptables API over D-Bus. All changes are made to iptables filter table and the changes are removed after tests are done.

%prep
%setup -q -n %{name}-%{version}

%build
make %{?_smp_mflags} release
make -C unit build

%check
make -C unit test

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/%{_libdir}/connman/plugins

mkdir -p %{buildroot}/%{_libdir}/connman/unit
install -m 744 unit/run_unit_tests %{buildroot}%{_libdir}/connman/unit/
install -m 744 unit/plugin_unit_test %{buildroot}%{_libdir}/connman/unit/

mkdir -p %{buildroot}/%{_libdir}/connman/test
install -m 744 test/test_script %{buildroot}%{_libdir}/connman/test/test_script

mkdir -p %{buildroot}/usr/share/dbus-1/system.d/
install -m 644 src/sailfish-iptables.conf %{buildroot}/usr/share/dbus-1/system.d/

%preun

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/connman/plugins/sailfish-connman-iptables-plugin.so
%config /usr/share/dbus-1/system.d/sailfish-iptables.conf

%files unit
%defattr(-,root,root,-)
%{_libdir}/connman/unit/*

%files test
%defattr(-,root,root,-)
%{_libdir}/connman/test/*
