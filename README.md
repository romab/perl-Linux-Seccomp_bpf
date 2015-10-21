# seccomp module for perl


## overview 
This module allows you easily whitelist systemcalls in your perl programs.
An example program is provided in examples/

The module only exports one function, 
scmp_bpf_install_filter, which takes a list as an argument..

Example:


```perl
use strict;
use Linux::Seccomp_bpf;

my @whitelist = (#"write",
                 "exit_group",
                 "rt_sigaction",
                 "read",);
print "foo\n";
&scmp_bpf_install_filter(@whitelist);
#program dies now, there is no write syscall anymore.
print "bar\n";
```


## credits
special thanks to mue for hacking on this.
