#!/usr/bin/perl

=head1 NAME

docsis.pl - Encode and decode DOCSIS config files

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

 docsis.pl [options] --decode <file> [--out <file>];
 docsis.pl [options] --encode <file> [--out <file>];

 Normal decoding:
 docsis.pl --decode config.bin --out config.json

 Decoding with extra information
 docsis.pl --decode config.bin --out config.json --advanced

 Encoding with shared secret
 docsis.pl --encode <file> --out <file> --secret "mysecret"

=head1 OPTIONS

=over

=item --decode <path>

=item --encode <path>

=back

File to encode or decode.

=head1 OPTIONS

=over

=item --out <str>

File to write. Default is STDOUT.

=item --secret <str>

Sets which shared secret to use, when encoding a binary file.

=item --advanced

Turns on advanced output, when decoding a binary file.

=item --trace

Turns on full debugging.

=item --version

Prints version.

=item --usage

Prints usage.

=item --help

Prints this help text.

=back

=cut

BEGIN {
    for my $module (qw/ autodie FindBin Getopt::Long JSON /) {
        eval "use $module (); 1" or die "The '$module' module is required. Run 'cpan -i $module' to install it";
    }
}

use strict;
use warnings;
use lib qq($FindBin::Bin/../lib);
use DOCSIS::ConfigFile;

our $VERSION = $DOCSIS::ConfigFile::VERSION;
our $ARGS = {};

Getopt::Long->import(qw/:config auto_help auto_version/);
GetOptions($ARGS, qw/
    decode=s
    encode=s
    out|o=s
    advanced|a
    secret|s=s
/) or Getopt::Long::HelpMessage();

my $docsis = DOCSIS::ConfigFile->new(
                 advanced_output => ($ARGS->{'advanced'} ? 1 : 0),
                 shared_secret   => $ARGS->{'secret'},
             );

if($ARGS->{'encode'}) {
    open my $FH, '<', $ARGS->{'encode'};
    my $config = JSON->new->ascii->decode(do { local $/; <$FH> });
    output($docsis, $docsis->encode($config));
}
elsif($ARGS->{'decode'}) {
    my $config = $docsis->decode($ARGS->{'decode'});
    output($docsis, JSON->new->pretty->ascii->encode($config));
}
else {
    Getopt::Long::HelpMessage();
}

exit 0;

=head1 FUNCTIONS

=head2 output

=cut

sub output {
    my $docsis = shift;
    my $data   = join "", @_;

    if($ARGS->{'out'}) {
        open my $FH, '>', $ARGS->{'out'};
        print $FH $data;
        close $FH;
    }
    else {
        print $data;
    }
}

=head1 AUTHOR

Jan Henning Thorsen C<< jhthorsen at cpan.org >>

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

Copyright (c) 2007 Jan Henning Thorsen

=cut
