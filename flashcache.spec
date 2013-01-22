# The kernel version you are building for
%{!?kernel_version:%define kernel_version %(uname -r)}

# The version of the module,
%{!?modversion:%define modversion %(if [ -d .git ]; then git describe --abbrev=0 --tags; else echo 2.0; fi)}

# Which revision are we on, increment per RPM build
%{!?pkgrelease:%define pkgrelease 1}

#### You shouldn't need to set the vars below

%define kernel kernel-%{kernel_version}

# The name of the module you are supplying
%define modname flashcache

# Define git commit revision, if we're in a repo
%define commit_rev %(if [ -d .git ]; then git describe --always --abbrev=12; else echo ''; fi)

# The path to the module, after it is installed
%define modpath /lib/modules/%{kernel_version}/extra/flashcache/

%define make_opts %{?_smp_mflags} COMMIT_REV=%{commit_rev} RHEL5_VER=

Name: %{modname}-%{kernel_version}
Summary: %{modname} Kernel Module for the %{kernel_version} kernel
Version: %{modversion}
Release: %{pkgrelease}
Source: %{modname}-%{modversion}.tar.gz
Epoch: 0
License: GPL
Group: System Environment/Kernel
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Requires: modutils kernel-devel
Provides: kernel-module-%{modname} = %{epoch}:%{version}

%description
This package provides a %{modname} kernel module for
kernel %{kernel_version}.

%prep
%setup -q -n %{modname}-%{modversion}

%build
make %{make_opts} KERNEL_SOURCE_VERSION=%{kernel_version}

%install
rm -rf %{buildroot}
cd src
make %{make_opts} DESTDIR=%{buildroot} utils_install ocf_install
install -d %{buildroot}/%{modpath}/
install -m 644 flashcache.ko %{buildroot}/%{modpath}/%{modname}.ko

%post
/sbin/depmod -a %{kernel_version}

%postun
/sbin/depmod -a %{kernel_version}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc README LICENSE
/sbin/*
%{modpath}/%{modname}.ko
/usr/lib/ocf/resource.d/%{modname}/%{modname}
