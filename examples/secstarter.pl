#!/usr/bin/perl
use strict;
use warnings;

use Linux::Seccomp_bpf;

my @whitelist = (#"write",
                 "exit_group",
                 "rt_sigaction",
                 "read",);
print "foo\n";
&scmp_bpf_install_filter(@whitelist);
#program dies now, there is no write syscall. 
print "bar\n";
