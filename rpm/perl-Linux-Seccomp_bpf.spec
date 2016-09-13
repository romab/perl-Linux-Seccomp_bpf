Name:           perl-Linux-Seccomp
Version:        0.3
Release:        1%{?dist}
Summary:        Filter syscalls via seccomp
License:        CHECK(Distributable)
Group:          Development/Libraries
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      x86_64
BuildRequires:  libseccomp
BuildRequires:  libseccomp-devel
Requires:       perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
Requires:       libseccomp

%description
Linux::Seccomp provides methods to load a whitelist of syscalls allowd in your perl program

%prep

%build
%{__perl} Makefile.PL INSTALLDIRS=vendor
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

make pure_install PERL_INSTALL_ROOT=$RPM_BUILD_ROOT

find $RPM_BUILD_ROOT -type f -name .packlist -exec rm -f {} \;
find $RPM_BUILD_ROOT -depth -type d -exec rmdir {} 2>/dev/null \;

%{_fixperms} $RPM_BUILD_ROOT/*

%check
make test

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc Changes README
/usr/lib64/perl5/vendor_perl/*
%{_mandir}/man3/*

%changelog
