package DOCSIS::ConfigFile;

=head1 NAME

DOCSIS::ConfigFile - Decodes and encodes DOCSIS config-files

=head1 VERSION

0.6004

=head1 SYNOPSIS

    use DOCSIS::ConfigFile;
    use JSON;

    my $obj     = DOCSIS::ConfigFile->new(
                      shared_secret   => '', # default
                      advanced_output => 0,  # default
                  );

                  $obj->shared_secret("foobar");
    my $encoded = $obj->encode([ {...}, {...}, ... ]);
    my $decoded = $obj->decode($filename);
                  $obj->advanced_output(1);
    my $dec_adv = $obj->decode(\$encoded);

    # see simple config in JSON format
    print JSON->new->pretty->decode($decoded);

    # see advanced config in JSON format
    print JSON->new->pretty->decode($dec_adv);

=head1 DESCRIPTION

An instance from this class can be used to encode or decode
L<DOCSIS|http://www.cablelabs.com> (Data over Cable Service Interface
Specifications) config files. These files are usually served using a
L<TFTP server|POE::Component::TFTPd>, after a
L<cable modem|http://en.wikipedia.org/wiki/Cable_modem> or MTA
(Multimedia Terminal Adapter) has recevied an IP address from a
L<DHCP|Net::ISC::DHCPd> server. These files are
L<binary encode|DOCSIS::ConfigFile::Encode> using a variety of
functions, but all the data in the file are constructed by TLVs
(type-length-value) blocks. These can be nested and concatenated.

This module is used as a layer between any human readable data and
the binary structure. The config file in human readable format can
look something like this:

    [
        { name => NetworkAccess => value => 1 },
        { name => GlobalPrivacyEnable => value => 1 },
        { name => MaxCPE => value => 10 },
        { name => BaselinePrivacy =>
            nested => [
                { name => AuthTimeout => value => 10 },
                { name => ReAuthTimeout => value => 10 },
                { name => AuthGraceTime => value => 600 },
                { name => OperTimeout => value => 1 },
                { name => ReKeyTimeout => value => 1 },
                { name => TEKGraceTime => value => 600 },
                { name => AuthRejectTimeout => value => 60 },
                { name => SAMapWaitTimeout => value => 1 },
                { name => SAMapMaxRetries => value => 4 }
            ]
        },
    ]

There is also an optional L</advanced_output> flag which can include
more information, but this is what is required/default: An array-ref
of hash-refs, containing a C<name> and a C<value> (or C<nested> for
nested data structures). The rest will this module figure out.

=head1 FAULT HANDLING

As for version C<0.60>, this module has changed from holding errors
in an attribute to actively reporting errors, using C<confess()>,
C<carp()> and the module L<autodie> for reporting system errors from
C<open()> and friends. Constructing the object, and changing attribute
values are still safe to do, but L</encode> and L</decode> might die.

=cut

use strict;
use warnings;
use autodie;
use Carp qw/ carp confess /;
use Digest::MD5;
use Digest::HMAC_MD5;
use DOCSIS::ConfigFile::Syminfo;
use DOCSIS::ConfigFile::Decode;
use DOCSIS::ConfigFile::Encode;

use constant Syminfo => "DOCSIS::ConfigFile::Syminfo";
use constant Decode  => "DOCSIS::ConfigFile::Decode";
use constant Encode  => "DOCSIS::ConfigFile::Encode";

our $VERSION = eval '0.6004';
our $TRACE   = 0;

=head1 ATTRIBUTES

=head2 shared_secret

Sets or gets the shared secret.

=cut

sub shared_secret {
    my $self = shift;
    $self->{'shared_secret'} = $_[0] if(@_);
    return $self->{'shared_secret'} ||= q();
}

=head2 advanced_output

Sets weither advanced output should be enabled. Takes 0 or 1 as argument.
Advanced output is off (0) by default.

=cut

sub advanced_output {
    my $self = shift;
    $self->{'advanced_output'} = $_[0] if(@_);
    return $self->{'advanced_output'} || 0;
}

=head1 METHODS

=head2 new

    $self = $class->new(\%args);

Arguments can be:

 shared_secret   => Shared secret in encoded cm config file
 advanced_output => Advanced decoded config format
 mibs            => will set $ENV{MIBS} to load custom mibs

=cut

sub new {
    my $class = shift;
    my $args = ref $_[0] eq 'HASH' ? $_[0] : {@_};
    my $self = bless $args, $class;
    return $self;
}

=head2 decode

    $array_ref = $self->decode($path_to_file);
    $array_ref = $self->decode(\$binary_string);
    $array_ref = $self->decode($FH);

This method decodes a binary config file stored in either a file on disk,
a binary string, or a filehandle. It returns an array-ref of hashes,
containing the config as a perl data structure.

=cut

sub decode {
    no warnings 'newline'; # don't shout on invalid filename

    my $self = shift;
    my $input = shift || '__undefined_input__';
    my $FH;

    if(ref $input eq 'SCALAR') { # binary string
        open $FH, '<', $input;
    }
    elsif(ref $input eq 'GLOB') { # input is filehandle
        $FH = $input;
    }
    elsif(-f $input) { # input is filename
        open $FH, '<', $input;
    }
    else {
        confess 'Usage: $self->decode( ScalarRef|GlobRef|Filename )';
    }

    binmode $FH;
    $self->{'decode_fh'} = $FH;

    return $self->_decode_loop;
}

sub _decode_loop {
    my $self    = shift;
    my $tlength = shift || 0xffffffff;
    my $p_code  = shift || 0;
    my $FH      = $self->{'decode_fh'};
    my $cfg     = [];

    CODE:
    while($tlength > 0) {
        my $code = $self->_read_code($FH) or last CODE;
        my $syminfo = Syminfo->from_code($code, $p_code);
        my $length = $self->_read_length($FH, $syminfo->length);
        my($value, $nested);

        $tlength -= $length + 2;

        if(!defined $syminfo->func) {
            #carp sprintf 'PCODE/CODE (%s/%s) gets skipped: No function to decode', $p_code, $code;
            next CODE;
        }
        elsif($syminfo->func eq 'nested') {
            $nested = $self->_decode_loop($length, $syminfo->code);
        }
        elsif(my $decoder = Decode->can($syminfo->func)) {
            ($value, $nested) = $decoder->( $self->_read_value($FH, $length) );
        }
        else {
            $self->_read_value($FH, $length);
            carp sprintf 'Unknown decode method for PCODE/CODE (%s/%s). (%s) bytes are thrown away', $p_code, $code, $length;
            next CODE;
        }

        if(defined $value or defined $nested) {
            push @$cfg, $self->_value_to_cfg($syminfo, $length, $value, $nested);
            next CODE;
        }

        carp sprintf 'Could not decode PCODE/CODE (%s/%s) using function (%s)', $p_code, $code, $syminfo->func;
    }

    return $cfg;
}

sub _read_code {
    my($self, $FH) = @_;
    my $bytes = read $FH, my($data), 1;

    return $bytes ? unpack 'C', $data : '';
}

sub _read_length {
    my $self = shift;
    my $read = read $_[0], my($length), $_[1];

    # Document: PKT-SP-PROV1.5-I03-070412
    # Chapter:  9.1 MTA Configuration File
    return $read == 0 ? 0
         : $read == 1 ? unpack('C', $length)
         : $read == 2 ? unpack('n', $length)
         :              0xffffffff # weird way to enforce error later on...
         ;
}

sub _read_value {
    my($self, $FH, $length) = @_;
    my $bytes = read $FH, my($data), $length;

    if($bytes != $length) {
        confess sprintf 'Expected to read (%s) bytes. Read (%s) bytes', $length, $bytes;
    }

    return $data;
}

sub _value_to_cfg {
    my $self    = shift;
    my $syminfo = shift;
    my $length  = shift;
    my $value   = shift;
    my $nested  = shift;

    if($self->advanced_output) {
        return {
            name   => $syminfo->id,
            code   => $syminfo->code,
            pcode  => $syminfo->pcode,
            func   => $syminfo->func,
            llimit => $syminfo->l_limit,
            ulimit => $syminfo->u_limit,
            length => $length,
            (defined $value  ? (value  => $value ) : ()),
            (defined $nested ? (nested => $nested) : ()),
        };
    }
    else {
        return {
            name => $syminfo->id,
            (defined $value  ? (value  => $value ) : ()),
            (defined $nested ? (nested => $nested) : ()),
        };
    }
}

=head2 encode

    $binary_str = $self->encode([ { ... }, ... ]);

Encodes an array of hashes, containing the DOCSIS config-file settings and
returns a binary encoded string. See L</DESCRIPTION> and the unit tests for
example input. For other structures, see the table generated by
L<DOCSIS::ConfigFile::Syminfo/dump_symbol_tree>.

=cut

sub encode {
    my $self   = shift;
    my $config = shift || '__undefined_input__';

    if(ref $config ne 'ARRAY') {
        confess 'Usage: $self->encode( ArrayRef[HashRef] )';
    }

    $self->{'cmts_mic'}  = {};
    $self->{'binstring'} = $self->_encode_loop($config) || q();

    if(grep { $_->{'name'} eq 'MtaConfigDelimiter' } @$config) {
        $self->{'_MtaConfigDelimiter'} = 1; # for internal usage
    }
    else {
        $self->{'_DefaultConfigDelimiter'} = 1; # for internal usage

        my $cm_mic   = $self->_calculate_cm_mic;
        my $cmts_mic = $self->_calculate_cmts_mic;
        my $eod_pad  = $self->_calculate_eod_and_pad;

        $self->{'binstring'} .= "$cm_mic$cmts_mic$eod_pad";
    }

    return $self->{'binstring'};
}

sub _encode_loop {
    my $self      = shift;
    my $config    = shift || '__undefined_input__';
    my $level     = shift || 0;
    my $i         = shift || 0;
    my $binstring = q();

    if(ref $config ne 'ARRAY') {
        confess sprintf 'Input is not an array ref: %s', $config;
    }

    TLV:
    for my $tlv (@$config) {
        confess sprintf 'Invalid TLV#%s: %s', $i, $tlv || '__undefined_tlv__' unless(ref $tlv eq 'HASH');
        confess sprintf 'Missing name in TLV#%s: %s', $i, join(',', keys %$tlv) unless($tlv->{'name'});

        my $name = $tlv->{'name'};
        my $syminfo = Syminfo->from_id($name);
        my($type, $length, $value);

        if(!defined $syminfo->func) {
            #carp sprintf 'TLV#%s/%s is skipped: No function to encode', $i, $name;
            next TLV;
        }
        elsif($syminfo->func eq 'nested') {
            $value = $self->_encode_loop($tlv->{'nested'}, $level+1, $i);
        }
        elsif(my $encoder = Encode->can($syminfo->func)) {
            $value = pack 'C*', $encoder->($tlv) or next TLV;
        }
        else {
            carp sprintf 'Unknown encode method for TLV#%s/%s', $i, $name;
            next TLV;
        }

        $syminfo = $self->_syminfo_from_syminfo_siblings($syminfo, \$value);
        $type = $syminfo->code;
        $length = ($syminfo->length == 2) ? pack('n', length $value) : pack('C', length $value);

        #carp 'name=%s type=%i, length=%i', $name, $type, length($value);

        $type = pack "C", $type;
        $binstring .= "$type$length$value";

        $self->_calculate_cmts_mic($name, "$type$length$value");
    }
    continue {
        $i++;
    }

    return $binstring;
}

sub _syminfo_from_syminfo_siblings {
    my($self, $syminfo, $value) = @_;
    my @error;

    SIBLING:
    for my $sibling (@{ $syminfo->siblings }) {
        unless($sibling->l_limit or $sibling->u_limit) {
            next SIBLING;
        }

        my $length = $$value =~ /^\d+$/ ? $$value : length $$value;

        if($length > $sibling->u_limit) {
            push @error, sprintf '%s/%s: %s > %s', $sibling->pcode, $sibling->code, $length, $sibling->u_limit;
        }
        elsif($length < $sibling->l_limit) {
            push @error, sprintf '%s/%s: %s < %s', $sibling->pcode, $sibling->code, $length, $sibling->l_limit;
        }
        else {
            return $sibling;
        }
    }

    confess sprintf 'Invalid value for %s: %s', $syminfo->id, join(', ', @error) if(@error);
    return $syminfo;
}

sub _calculate_eod_and_pad {
    my $self   = shift;
    my $length = length $self->{'binstring'};
    my $pads   = 4 - (1 + $length) % 4;

    return pack("C", 255) .("\0" x $pads);
}

sub _calculate_cm_mic {
    my $self   = shift;
    my $cm_mic = pack("C*", 6, 16) .Digest::MD5::md5($self->{'binstring'});

    $self->_calculate_cmts_mic("CmMic", $cm_mic);

    return $cm_mic;
}

sub _calculate_cmts_mic {
    my $self     = shift;
    my $cmts_mic = $self->{'cmts_mic'};
    my $data;

    if(@_ == 2) {
        my $name = shift;
        my $val  = shift;
        return $cmts_mic->{ $name } .= $val;
    }
    else {
        for my $code (Syminfo->cmts_mic_codes) {
            $data .= $cmts_mic->{$code} || '';
        }

        return(join "",
            pack("C*", 7, 16),
            Digest::HMAC_MD5::hmac_md5($data, $self->shared_secret),
        );
    }
}

=head1 CONSTANTS

=head2 Decode

Returns L<DOCSIS::ConfigFile::Decode>.

=head2 Encode

Returns L<DOCSIS::ConfigFile::Encode>.

=head2 Syminfo

Returns L<DOCSIS::ConfigFile::Syminfo>.

=cut

=head1 AUTHOR

Jan Henning Thorsen, C<< <pm at flodhest.net> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-docsis-perl at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=DOCSIS-ConfigFile>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc DOCSIS::ConfigFile

You can also look for information at
L<http://search.cpan.org/dist/DOCSIS-ConfigFile>

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

Copyright (c) 2007 Jan Henning Thorsen

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

DOCSIS is a registered trademark of Cablelabs, http://www.cablelabs.com

This module got its inspiration from the program docsis, http://docsis.sf.net.

=cut

1;
