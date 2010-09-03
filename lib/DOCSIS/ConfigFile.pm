package DOCSIS::ConfigFile;

=head1 NAME

DOCSIS::ConfigFile - Decodes and encodes DOCSIS config-files

=head1 VERSION

0.5901

=head1 SYNOPSIS

    use DOCSIS::ConfigFile;
    use YAML;

    my $obj     = DOCSIS::ConfigFile->new(
                      shared_secret   => '', # default
                      advanced_output => 0,  # default
                  );

                  $obj->shared_secret("foobar");
    my $encoded = $obj->encode([ {...}, {...}, ... ]);
    my $decoded = $obj->decode($filename);
                  $obj->advanced_output(1);
    my $dec_adv = $obj->decode(\$encoded);

    print YAML::Dump($decoded); # see simple config in YAML format
    print YAML::Dump($dec_adv); # see advanced config in YAML format

=cut

use strict;
use warnings;
use autodie;
use Digest::MD5;
use Digest::HMAC_MD5;
use DOCSIS::ConfigFile::Syminfo;
use DOCSIS::ConfigFile::Decode;
use DOCSIS::ConfigFile::Encode;

use constant Syminfo => "DOCSIS::ConfigFile::Syminfo";
use constant Decode  => "DOCSIS::ConfigFile::Decode";
use constant Encode  => "DOCSIS::ConfigFile::Encode";

our $VERSION = '0.5901';
our $TRACE   = 0;

=head1 METHODS

=head2 new(%args)

Object constructor.

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

Decodes a binary config-file. Needs only one of these arguments: Filehandle,
path to file or reference to a binary string.

Returns an array-ref of hashes, containing the config as a perl data
structure.

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
        my($value, $nested, $func);

        my $code     = $self->_read_code($FH) or last CODE;
        my $syminfo  = Syminfo->from_code($code, $p_code);
        my $length   = $self->_read_length($FH, $syminfo->length);

        $tlength -= $length + 2;

        if(!$syminfo->func) {
            carp sprintf 'Undefined decode function for PCODE/CODE (%s/%s)', $p_code, $code;
            last CODE;
        }
        elsif($syminfo->func eq 'nested') {
            $nested = $self->_decode_loop($length, $syminfo->code);
        }
        else {
            my $bytes = read $FH, my($data), $length;

            if($bytes != $length) {
                confess sprintf 'Read (%s) bytes instead of (%s) while decoding PCODE/CODE (%s/%s)', $bytes, $length, $p_code, $code;
            }

            if($func = Decode->can($syminfo->func)) {
                ($value, $nested) = $func->($data);
            }
            else {
                $data = Decode->can('string')->($data);
                $value = sprintf 'Unknown TLV: T=%s/%s L=%s, V=%s', $p_code, $code, $length, $data;
                carp $value;
            }
        }
    
        if(defined $value or defined $nested) {
            push @$cfg, $self->_value_to_cfg($syminfo, $length, $value, $nested);
            next CODE;
        }

        carp sprintf 'Could not decode PCODE/CODE (%s/%s) using function (%s)', $p_code, $code, $func;
    }

    return $cfg;
}

sub _read_code {
    my $self = shift;
    my $FH = shift;
    my $code;

    read $FH, $code, 1;

    return unpack 'C', $code;
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

Encodes an array of hashes, containing the DOCSIS config-file settings. Takes
only on argument: An array-ref of hashes.

Returns a binary string.

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

        unless(ref $tlv eq 'HASH') {
            confess sprintf 'Invalid TLV#%s: %s', $i, $tlv || '__undefined_tlv__';
        }
        unless($tlv->{'name'}) {
            confess sprintf 'Missing name in TLV#%s: %s', $i, join(',', keys %$tlv);
        }

        my $name    = $tlv->{'name'};
        my $syminfo = Syminfo->from_id($name);
        my($type, $length, $value, @error);

        unless($syminfo->func) {
            carp sprintf 'Unknown encode method for TLV#%s/%s', $i, $name;
            next TLV;
        }

        if($syminfo->func eq 'nested') {
            $value = $self->_encode_loop($tlv->{'nested'}, $level+1, $i);
        }
        else {
            my $sub = Encode->can($syminfo->func);

            unless($sub) {
                carp sprintf 'Unknown encode method for TLV#%s/%s', $i, $name;
                next TLV;
            }
            unless(defined $tlv->{'value'}) {
                confess sprintf 'Missing value in TLV#%s/%s', $i, $name;
                next TLV;
            }

            unless(defined( $value = $sub->($tlv) )) {
                carp sprintf 'Undefined encoded value for TLV#%s/%s', $i, $name;
                next TLV;
            }

            $value = pack 'C*', @$value;
        }

        SIBLING:
        for my $o (@{ $syminfo->siblings }) {
            next unless($o->l_limit or $o->u_limit);

            my $length = $tlv->{'value'} =~ /^\d+$/ ? $tlv->{'value'} : length $value;

            if($length > $o->u_limit) {
                push @error, sprintf '%s/%s: %s > %s', $o->pcode, $o->code, $length, $o->u_limit;
            }
            elsif($length < $o->l_limit) {
                push @error, sprintf '%s/%s: %s < %s', $o->pcode, $o->code, $length, $o->l_limit;
            }
            else {
                $syminfo = $o;
                @error   = ();
                last SIBLING;
            }
        }

        if(@error) {
            confess sprintf 'Invalid value for %s: %s', $name, join(', ', @error);
        }

        $type   = $syminfo->code;
        $length = ($syminfo->length == 2) ? pack("n", length $value)
                :                           pack("C", length $value);

        #carp 'name=%s type=%i, length=%i', $name, $type, length($value);

        $type       = pack "C", $type;
        $binstring .= "$type$length$value";

        $self->_calculate_cmts_mic($name, "$type$length$value");
    }
    continue {
        $i++;
    }

    return $binstring;
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

=head2 shared_secret

Sets or gets the shared secret.

=cut

sub shared_secret {
    my $self = shift;
    $self->{'shared_secret'} = shift if(@_);
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
