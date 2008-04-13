
#==========================
package DOCSIS::ConfigFile;
#==========================

use strict;
use warnings;
use Digest::MD5;
use Digest::HMAC_MD5;
use constant syminfo_class => "DOCSIS::ConfigFile::Syminfo";
use constant decode_class  => "DOCSIS::ConfigFile::Decode";
use constant encode_class  => "DOCSIS::ConfigFile::Encode";
use DOCSIS::ConfigFile::Logger;
use DOCSIS::ConfigFile::Syminfo;
use DOCSIS::ConfigFile::Decode;
use DOCSIS::ConfigFile::Encode;

our $VERSION = '0.5';


BEGIN { #=====================================================================
    no strict 'refs';
    my %subs = (
        shared_secret   => q(),
        log             => undef,
        advanced_output => undef,
    );

    for my $sub (keys %subs) {
        *$sub = sub {
            my $self = shift;
            $self->{"__$sub"} = shift if(defined $_[0]);
            return $self->{"__$sub"} || $subs{$sub};
        };
    }
}


sub decode { #================================================================
    no warnings 'newline'; # don't shout on invalid filename

    my $self  = shift;
    my $input = shift;
    my $FH;

    ### no input
    if(not defined $input) {
        $self->log->error("Need 'something' to decode");
        return;
    }

    ### input is a binary string
    elsif(ref $input eq 'SCALAR') {
        open($FH, "<", $input);
    }

    ### input is filehandle
    elsif(ref $input eq 'GLOB') {
        $self->log->debug("Decoding from filehandle");
    }

    ### input is file
    elsif(-f $input) {
        unless(open($FH, "<", $input)) {
            $self->log->error("Could not decode from $input: $!");
            return;
        }
    }

    ### check filehandle
    if(ref $FH eq 'GLOB') {
        binmode $FH;
        $self->{'decode_fh'} = $FH;
    }
    else {
        $self->log->error("Could not set up filehandle for decoding");
        return;
    }

    return $self->_decode_loop;
}

sub _decode_loop { #==========================================================

    my $self         = shift;
    my $total_length = shift || 0xffffffff;
    my $p_code       = shift || 0;
    my $FH           = $self->{'decode_fh'};
    my $cfg          = [];

    BYTE:
    while($total_length > 0) {
        my($code, $length, $syminfo, $value, $nested);

        ### read data header
        unless(read $FH, $code, 1) {
            $self->log->debug("Could not read \$code: $!");
            last BYTE;
        }
        unless(read $FH, $length, 1) {
            $self->log->debug("Could not read \$length: $!");
            last BYTE;
        }

        ### fix data
        $code          = unpack("C", $code);
        $length        = unpack("C", $length) or next BYTE;
        $total_length -= $length + 2;
        $syminfo       = syminfo_class->from_code($code, $p_code);

        ### nested block
        if($syminfo->func eq 'nested') {
            $nested = $self->_decode_loop($length, $syminfo->code);
        }

        ### flat block
        else {

            ### decode function does not exist
            unless(decode_class->can($syminfo->func)) {
                $self->log->debug("decode function does not exist");
                $syminfo->undefined_func($code, $p_code);
            }

            ### read and decode
            read($FH, my $data, $length);
            ($value, $nested) = decode_class->can($syminfo->func)->($data);
        }
    
        ### save data
        if(defined $value or defined $nested) {
            push @$cfg, $self->_value_to_cfg(
                            $syminfo, $length, $value, $nested
                        );
        }

        ### no data
        else {
            $self->log->error(
                q(Could not decode data using ') .$syminfo->func .q(')
            );
        }
    }

    return $cfg;
}

sub _value_to_cfg { #=========================================================

    my $self    = shift;
    my $syminfo = shift;
    my $length  = shift;
    my $value   = shift;
    my $nested  = shift;

    ### return config
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

sub encode { #================================================================

    my $self   = shift;
    my $config = shift;

    ### check config
    if(ref $config ne 'ARRAY') {
        $self->log->error("Input is not an array ref");
        return;
    }

    ### encode data
    $self->{'_cmts_mic'}  = {};
    $self->{'_binstring'} = $self->_encode_loop($config);

    ### mta config file
    if(grep { $_->{'name'} eq 'MtaConfigDelimiter' } @$config) {
        $self->log->debug("Setting up MTA config-file");
    }

    ### add special cm params
    else {
        $self->log->debug("Setting up CM config-file");

        ### calculate mic, eod and pad
        my $cm_mic   = $self->_calculate_cm_mic;
        my $cmts_mic = $self->_calculate_cmts_mic;
        my $eod_pad  = $self->_calculate_eod_and_pad;

        $self->{'_binstring'} .= "$cm_mic$cmts_mic$eod_pad";
    }

    return $self->{'_binstring'};
}

sub _encode_loop { #==========================================================

    my $self      = shift;
    my $config    = shift;
    my $level     = shift || 0;
    my $binstring = q();

    ### check config
    if(ref $config ne 'ARRAY') {
        $self->log->error("Not an array: " .ref $config);
        return q();
    }

    TLV:
    for my $tlv (@$config) {

        my $name    = $tlv->{'name'} or next TLV;
        my $syminfo = syminfo_class->from_id($name);
        my $sub     = encode_class->can($syminfo->func);
        my $code    = $syminfo->code;
        my $type    = pack "C", $code;

        ### nested tlv
        if($syminfo->func eq 'nested') {

            ### set binstring
            my $value   = $self->_encode_loop($tlv->{'nested'}, $level + 1);
            my $length  = pack "C", length $value;
            $binstring .= "$type$length$value";

            $self->_calculate_cmts_mic($name, "$type$length$value");

            $self->log->trace(sprintf
                q(Added nested data %s/%i [%i] 0x%s),
                $name, $code, length($value), join("", unpack "H*", $value),
            );

            ### skip ahead
            next TLV;
        }

        ### don't know what to do
        elsif(!$sub) {
            $self->log->error("Unknown encode method for $name");
            next TLV;
        }

        ### check value range
        if($syminfo->l_limit or $syminfo->u_limit) {
            my $value = ($tlv->{'value'} =~ /\D/) ? hex $tlv->{'value'}
                      :                                 $tlv->{'value'};
            if($value > $syminfo->u_limit) {
                $self->log->error("Value too high: $name=$value");
                next TLV;
            }
            if($value < $syminfo->l_limit) {
                $self->log->error("Value too low: $name=$value");
                next TLV;
            }
        }

        ### set type, length and value
        my $data   = $sub->($tlv) or next TLV;
        my $length = pack "C", int(@$data);
        my $value  = pack "C*", @$data;

        ### check value length
        if(length $value > 255) {
            next TLV;
        }

        ### save data to binstring
        $binstring .= "$type$length$value";

        $self->log->trace(sprintf
            q/%s %i|%i|%s/,
            $name, $code, length($value), join("", unpack "H*", $value),
        );

        $self->_calculate_cmts_mic($name, "$type$length$value");
    }

    return $binstring;
}

sub _calculate_eod_and_pad { #================================================

    my $self   = shift;
    my $length = length $self->{'_binstring'};
    my $pads   = 4 - (1 + $length) % 4;

    return pack("C", 255) .("\0" x $pads);
}

sub _calculate_cm_mic { #=====================================================

    my $self   = shift;
    my $cm_mic = pack("C*", 6, 16) .Digest::MD5::md5($self->{'_binstring'});

    ### add to cmts mic calculation
    $self->_calculate_cmts_mic("CmMic", $cm_mic);

    return $cm_mic;
}

sub _calculate_cmts_mic { #===================================================

    my $self     = shift;
    my $cmts_mic = $self->{'_cmts_mic'};
    my $data;

    ### add
    if(@_ == 2) {
        my $name = shift;
        my $val  = shift;
        return $cmts_mic->{ $name } .= $val;
    }

    ### get mic
    else {
        for my $code (syminfo_class->cmts_mic_codes) {
            $data .= $cmts_mic->{$code} || '';
        }

        return(join "",
            pack("C*", 7, 16),
            Digest::HMAC_MD5::hmac_md5($data, $self->shared_secret),
        );
    }
}

sub new { #===================================================================

    my $class  = shift;
    my %args   = @_;
    my $self   = bless {}, $class;

    ARGUMENT:
    for my $k (keys %args) {
        next ARGUMENT unless($self->can($k));
        $self->$k($args{$k});
    }

    $self->log( DOCSIS::ConfigFile::Logger->new );

    ### load mibs
    $ENV{'MIBS'} = (defined $self->{'mibs'}) ? $self->{'mibs'} : 'ALL';

    return $self;
}

#=============================================================================
1983;
__END__

=head1 NAME

DOCSIS::ConfigFile - Decodes and encodes DOCSIS config-files for cablemodems

=head1 VERSION

Version 0.5

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
 
=head1 METHODS

=head2 new

Object constructor.

=head2 decode

Decodes a binary config-file. Needs only one of these arguments: Filehandle,
path to file or reference to a binary string.

Returns an array-ref of hashes, containing the config as a perl data
structure.

=head2 encode

Encodes an array of hashes, containing the DOCSIS config-file settings. Takes
only on argument: An array-ref of hashes.

Returns a binary string.

=head2 shared_secret

Sets or gets the shared secret.

=head2 advanced_output

Sets weither advanced output should be enabled. Takes 0 or 1 as argument.
Advanced output is off (0) by default.

=head2 log

Returns a log-handler. Log::Log4perl by default.

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
