mkdir -p $PWD/rpm/BUILD
cp -r ../* rpm/BUILD/
rpmbuild -v -bb \
        --define "_topdir $PWD/rpm" \
	--define "-srcdir .." \
        perl-Linux-Seccomp_bpf.spec
mv rpm/RPMS/x86_64/perl-Linux-Seccomp-0.1-1.el7.centos.x86_64.rpm .
rm -rf rpm 
