package DOCSIS::ConfigFile;

=head1 NAME

DOCSIS::ConfigFile - Decodes and encodes DOCSIS config-files

=head1 VERSION

Version 0.54

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
use Digest::MD5;
use Digest::HMAC_MD5;
use constant Syminfo => "DOCSIS::ConfigFile::Syminfo";
use constant Decode  => "DOCSIS::ConfigFile::Decode";
use constant Encode  => "DOCSIS::ConfigFile::Encode";
use DOCSIS::ConfigFile::Syminfo;
use DOCSIS::ConfigFile::Decode;
use DOCSIS::ConfigFile::Encode;

our $VERSION = '0.54';

=head1 METHODS

=head2 new(%args)

Object constructor.

Arguments can be:

 shared_secret   => Shared secret in encoded cm config file
 advanced_output => Advanced decoded config format
 mibs            => will set $ENV{MIBS} to load custom mibs
 log             => Custom logger

=cut

sub new {
    my $class = shift;
    my $self  = bless {@_}, $class;

    $self->{'log'} = _init_logger() unless($self->{'log'});

    return $self;
}

sub _init_logger {
    eval "require Log::Log4perl" or return;
    Log::Log4perl->initialized   or return;
    Log::Log4perl->get_logger    or return;
}

=head2 decode

Decodes a binary config-file. Needs only one of these arguments: Filehandle,
path to file or reference to a binary string.

Returns an array-ref of hashes, containing the config as a perl data
structure.

=cut

sub decode {
    no warnings 'newline'; # don't shout on invalid filename

    my $self  = shift;
    my $input = shift;
    my $FH;

    $self->{'error'} = [];

    if(not defined $input) { # no input
        $self->logger(error => "Need 'something' to decode");
        return;
    }
    elsif(ref $input eq 'SCALAR') { # binary string
        open($FH, "<", $input);
    }
    elsif(ref $input eq 'GLOB') { # input is filehandle
        $self->logger(debug => "Decoding from filehandle");
    }
    elsif(-f $input) { # input is filename
        unless(open($FH, "<", $input)) {
            $self->logger(error => "Could not decode from %s:%s", $input, $!);
            return;
        }
    }

    if(ref $FH eq 'GLOB') {
        binmode $FH;
        $self->{'decode_fh'} = $FH;
    }
    else {
        $self->logger(error => "Could not set up filehandle for decoding");
        return;
    }

    return $self->_decode_loop;
}

sub _decode_loop {
    my $self         = shift;
    my $total_length = shift || 0xffffffff;
    my $p_code       = shift || 0;
    my $FH           = $self->{'decode_fh'};
    my $cfg          = [];

    BYTE:
    while($total_length > 0) {
        my($code, $length, $syminfo, $value, $nested, $method);

        unless(read $FH, $code, 1) {
            $self->logger(error => 'Could not read $code: %s', $!);
            last BYTE;
        }
        unless(read $FH, $length, 1) {
            $self->logger(error => 'Could not read $length: %s', $!);
            last BYTE;
        }

        $code          = unpack("C", $code);
        $length        = unpack("C", $length) or next BYTE;
        $total_length -= $length + 2;
        $syminfo       = Syminfo->from_code($code, $p_code);

        if($syminfo->func eq 'nested') {
            $nested = $self->_decode_loop($length, $syminfo->code);
        }
        elsif(my $func = Decode->can($syminfo->func)) {
            read($FH, my $data, $length);
            ($value, $nested) = $func->($data);
        }
        else {
            $self->logger(debug => "Decode function does not exist");
            $syminfo->undefined_func($code, $p_code);
        }
    
        if(defined $value or defined $nested) {
            push @$cfg, $self->_value_to_cfg(
                            $syminfo, $length, $value, $nested
                        );
        }
        else {
            $self->logger(error => q(Could not decode data using '%s'),
                $syminfo->func
            );
        }
    }

    return $cfg;
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
    my $config = shift;

    $self->{'error'} = [];

    if(ref $config ne 'ARRAY') {
        $self->logger(error => "Input is not an array ref");
        return;
    }

    $self->{'cmts_mic'}  = {};
    $self->{'binstring'} = $self->_encode_loop($config);

    return $self->{'binstring'} = q() if(@{ $self->{'error'} });

    if(grep { $_->{'name'} eq 'MtaConfigDelimiter' } @$config) {
        $self->logger(debug => "Setting up MTA config-file");
    }
    else {
        $self->logger(debug => "Setting up CM config-file");

        my $cm_mic   = $self->_calculate_cm_mic;
        my $cmts_mic = $self->_calculate_cmts_mic;
        my $eod_pad  = $self->_calculate_eod_and_pad;

        $self->{'binstring'} .= "$cm_mic$cmts_mic$eod_pad";
    }

    return $self->{'binstring'};
}

sub _encode_loop {
    my $self      = shift;
    my $config    = shift;
    my $level     = shift || 0;
    my $i         = shift || 0;
    my $binstring = q();

    if(ref $config ne 'ARRAY') {
        $self->logger(error => "Not an array: %s" .ref($config));
        return q();
    }

    TLV:
    for my $tlv (@$config) {
        unless(ref $tlv eq 'HASH') {
            $self->logger(error => "Invalid TLV#$i");
            next TLV;
        }
        unless($tlv->{'name'}) {
            $self->logger(error => "Missing name in TLV#$i");
            next TLV;
        }

        my $name    = $tlv->{'name'};
        my $syminfo = Syminfo->from_id($name);

        unless($syminfo->func) {
            $self->logger(error => "Unknown encode method for %s", $name);
            next TLV;
        }

        my $code = $syminfo->code;
        my $type = pack "C", $code;
        my($sub, $data, $length, $value);

        #==========
        # is nested
        #==========

        if($syminfo->func eq 'nested') {
            my $value   = $self->_encode_loop($tlv->{'nested'}, $level+1, $i);
            my $length  = pack "C", length $value;
            $binstring .= "$type$length$value";

            $self->_calculate_cmts_mic($name, "$type$length$value");

            $self->logger(trace => q(Added nested data %s/%s [%i] 0x%s),
                $name, $code, length($value), join("", unpack "H*", $value),
            );

            next TLV;
        }

        #===========
        # not nested
        #===========

        unless($sub = Encode->can($syminfo->func)) {
            $self->logger(error => "Unknown encode method for %s", $name);
            next TLV;
        }
        unless(defined $tlv->{'value'}) {
            $self->logger(error => "Missing value in TLV#$i");
            next TLV;
        }

        if($syminfo->l_limit or $syminfo->u_limit) {
            my $value = ($tlv->{'value'} =~ /\D/) ? hex $tlv->{'value'}
                      :                                 $tlv->{'value'};
            if($value > $syminfo->u_limit) {
                $self->logger(error => "Value too high: %s=%i", $name, $value);
                next TLV;
            }
            if($value < $syminfo->l_limit) {
                $self->logger(error => "Value too low: %s=%i", $name, $value);
                next TLV;
            }
        }

        unless(defined( $data = $sub->($tlv) )) {
            $self->logger(error => "Undefined value for TLV#$i");
            next TLV;
        }

        $length = pack "C", int(@$data);
        $value  = pack "C*", @$data;

        if(length $value > 255) {
            $self->logger(error => "Value is too long in TLV#$i");
            next TLV;
        }

        $binstring .= "$type$length$value";

        $self->logger(trace => sprintf q(%s %i|%i|%s),
            $name, $code, length($value), join("", unpack "H*", $value),
        );

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
    $self->{'advanced_output'} = shift if(@_);
    return $self->{'advanced_output'} ||= q();
}

=head2 errors

Retrieves the errors if L<encode()> or L<decode()> fails.

=cut

sub errors {
    $_[0]->{'error'} ||= [];
    return wantarray ? @{ $_[0]->{'error'} } : $_[0]->{'error'};
}

=head2 logger

=cut

sub logger {
    my $self  = shift;
    my $level = shift;
    my $msg   = sprintf shift(@_), @_;
    my $log   = $self->{'log'};
    
    if($log) {
        $log->$level($msg);
    }

    if($level eq 'error') {
        push @{ $self->{'error'} }, $msg;
    }

    return 1;
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
