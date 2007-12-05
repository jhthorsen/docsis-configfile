#!/usr/bin/perl

#===============
# docsis_yaml.pl
#===============

use strict;
use warnings;
use DOCSIS::ConfigFile;
use Getopt::Euclid;
use YAML;

### init
my $docsis = DOCSIS::ConfigFile->new(
                 advanced_output => ($ARGV{'-advanced'} ? 1 : 0),
                 shared_secret   => $ARGV{'-secret'},
             );

### encode yaml
if(-T $ARGV{'-in'}) {
    my $config = YAML::LoadFile($ARGV{'-in'});
    output($docsis->encode($config));
}

### decode binary data
else {
    my $config = $docsis->decode($ARGV{'-in'});
    output(YAML::Dump($config));
}

### the end
exit 0;

sub output { #================================================================

    ### init
    my $data = join "", @_;

    ### write to file
    if($ARGV{'-out'}) {
        open(my $FH, ">", $ARGV{'-out'}) or die $!;
        print $FH $data;
        close $FH;
    }
    
    ### print to stdout
    else {
        print $data;
    }
}

#=============================================================================
__END__

=head1 NAME

docsis_yaml.pl

=head1 VERSION

Version 0.01

=head1 USAGE

 docsis_yaml.pl [options] -i <infile> [-o <outfile>];

# Normal decoding:
 docsis_yaml.pl -i config.bin -o config.yaml

# Decoding with extra information
 docsis_yaml.pl -i config.bin -o config.yaml -a

# Encoding with shared secret
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

=head1 AUTHOR

Jan Henning Thorsen < jan.henning at flodhest.net >

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

Copyright (c) 2007 Jan Henning Thorsen

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
675 Mass Ave, Cambridge, MA 02139, USA.

=cut
