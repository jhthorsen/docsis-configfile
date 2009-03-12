#!/usr/bin/perl

=head1 NAME

docsis_yaml.pl

=head1 VERSION

Version 0.01

=head1 USAGE

 docsis_yaml.pl [options] -i <infile> [-o <outfile>];

 Normal decoding:
 docsis_yaml.pl -i config.bin -o config.yaml

 Decoding with extra information
 docsis_yaml.pl -i config.bin -o config.yaml -a

 Encoding with shared secret
 docsis_yaml.pl -i config.yaml -o config.bin -s "mysecret"

=head1 REQUIRED ARGUMENTS

=over

=item -i[n] <str>

=back

File to read.

=head1 OPTIONS

=over

=item -o[ut] <str>

File to write. Default is STDOUT.

=item -s[ecret] <str>

Sets which shared secret to use, when encoding a binary file.

=item -a[dvanced]

Turns on advanced output, when decoding a binary file.

=item --version

Prints version.

=item --usage

Prints usage.

=item --help

Prints this help text.

=back

=cut

use strict;
use warnings;
use FindBin;
use lib qq($FindBin::Bin/../lib);
use DOCSIS::ConfigFile;
use Getopt::Long;
use YAML;

my $ARGS = {};

GetOptions($ARGS, qw/
    in|i=s out|o=s advanced|a secret|s=s trace
/) or Getoptions::HelpMessage();

$DOCSIS::ConfigFile::TRACE = $ARGS->{'trace'};

my $docsis = DOCSIS::ConfigFile->new(
                 advanced_output => ($ARGS->{'advanced'} ? 1 : 0),
                 shared_secret   => $ARGS->{'secret'},
             );

if(-T $ARGS->{'in'}) {
    my $config = YAML::LoadFile($ARGS->{'in'});
    output($docsis, $docsis->encode($config));
}
else {
    my $config = $docsis->decode($ARGS->{'in'});
    output($docsis, YAML::Dump($config));
}

exit 0;

=head1 FUNCTIONS

=head2 output

=cut

sub output {
    my $docsis = shift;
    my $data   = join "", @_;

    if(my @errors = $docsis->errors) {
        die join "\n", @errors, q();
    }

    if($ARGS->{'out'}) {
        open(my $FH, ">", $ARGS->{'out'}) or die $!;
        print $FH $data;
        close $FH;
    }
    
    else {
        print $data;
    }
}

=head1 AUTHOR

Jan Henning Thorsen < jan.henning at flodhest.net >

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

Copyright (c) 2007 Jan Henning Thorsen

=cut
