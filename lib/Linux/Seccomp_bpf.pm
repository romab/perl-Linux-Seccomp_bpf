package Linux::Seccomp_bpf;

use 5.016003;
use strict;
use warnings;
require 'syscall.ph';

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Linux::Seccomp_bpf ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );


our @EXPORT = qw(scmp_bpf_install_filter);


our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Linux::Seccomp_bpf', $VERSION);

# Preloaded methods go here.
sub scmp_bpf_install_filter {
    my $r = Linux::Seccomp_bpf::scmp_bpf_is_available();

    if (!$r) {
    printf("seccomp not available.");
    exit(1);
    }


    my @rules = @_;
    my @syscall_no;
    foreach my $call (@rules) {
    #prefix with sys.
       my $s;
       if ($call !~ /^SYS_/ ) {
            $s = "SYS_" . $call;
       }
       my $number;
       eval {
           $number = &{\&{$s}}();
       };
       if ($@) {
           printf("$s not a valid syscall\n");
           exit(2);
       }
       push(@syscall_no, $number);
    }
    return Linux::Seccomp_bpf::inl_scmp_bpf_install_filter(\@syscall_no);
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Linux::Seccomp_bpf - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Linux::Seccomp_bpf;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Linux::Seccomp_bpf, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

andreas, E<lt>andreas@localdomainE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 by andreas

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.16.3 or,
at your option, any later version of Perl 5 you may have available.


=cut
