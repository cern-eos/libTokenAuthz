Summary: TTokenAuthz authorization library
Name: tokenauthz
Version: 1.2.5
Release: 1
URL: none
Source0: %{name}-%{version}.tar.gz
License: OpenSource
#Prefix: /
Group: CERN
BuildRoot: %{_tmppath}/%{name}-root

BuildRequires: libxml2-devel, libcurl-devel, openssl-devel
BuildRequires: devtoolset-8
BuildRequires: devtoolset-8-binutils-devel

%description
This package contains the token authorization library.

The software and RPM packaging was provided by Andreas.Joachim.Peters@cern.ch [CERN] (EMAIL: andreas.joachim.peters@cern.ch).
& DerekFeichtinger [PSI] (EMAIL: derek.feichtinger@cern.ch).

%prep
%setup -q
%build
source /opt/rh/devtoolset-8/enable
./configure  --prefix=/usr --libdir=/usr/lib64 --includedir=/usr/include
make
%install
make DESTDIR=$RPM_BUILD_ROOT install
find $RPM_BUILD_ROOT \( -type f -o -type l \) -print \
    | sed "s#^$RPM_BUILD_ROOT/*#/#" > RPM-FILE-LIST

%clean
rm -rf $RPM_BUILD_ROOT

%files -f RPM-FILE-LIST
%defattr(-,root,root)

%changelog
* Tue Mar 06 2007 root <root@lxb1388.cern.ch>
- Initial build.
- 1.1.4 fixes for gcc 4.1
- 1.1.5 fixes CERT match bug
- 1.1.6 installs into /usr/
- 1.1.7 security fix for VO selection
- 1.1.8 disable the hardcoded debug setting
- 1.2.1 support for paths not startins with '/'
- 1.2.2 revert wrong fix in 1.2.1
- 1.2.3 fix potential buffer overflow in decodeEnvelope function
- 1.2.4 make initialization atomic and avoid continous calling RSA_size
- 1.2.5 add devtoolset-8 to build for atomic support
%post
%preun
%postun
echo 

