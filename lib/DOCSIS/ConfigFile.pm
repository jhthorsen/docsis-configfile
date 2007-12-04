
#==========================
package DOCSIS::ConfigFile;
#==========================

use strict;
use warnings;
use Digest::MD5;
use Digest::HMAC_MD5;
use DOCSIS::ConfigFile::Syminfo;
use DOCSIS::ConfigFile::Decode;
use DOCSIS::ConfigFile::Encode;
use Log::Log4perl;


our $VERSION       = '0.2';
our %BYTE_SIZE     = (
    'short int'   => 2,
    'int'         => 4,
    'long int'    => 4,
    'char'        => 1,
    'float'       => 4,
    'double'      => 8,
    'long double' => 12,
    'md5digest'   => 16,
);
our @cmts_mic_list = qw/
    1 2 3 4 17 43 6 18 19 20 22 23 24 25 28 29 26 35 36 37 40
/;
our $LOGCONFIG     = {
    "log4perl.rootLogger"             => "ERROR, screen",
    "log4perl.appender.screen"        => "Log::Log4perl::Appender::Screen",
    "log4perl.appender.screen.layout" => "Log::Log4perl::Layout::SimpleLayout",
};


sub decode { #================================================================

    ### init
    my $self = shift;
    my %args = @_;
    my $FH;

    ### setup args
    $self->{$_} = $args{$_} for(keys %args);

    ### no filehandle
    unless(ref $self->{'filehandle'} eq 'GLOB') {

        ### read from file on disk
        if($self->{'read_file'} and -r $self->{'read_file'}) {
            if(open($FH, '<', $self->{'read_file'})) {
                binmode $FH;
                $self->{'filehandle'} = $FH;
            }
            else {
                $self->log->error("Could not open read_file: $!");
                return;
            }
        }

        ### read from string
        elsif($self->{'binstring'}) {
            open($FH, '<', \$self->{'binstring'});
            binmode $FH;
            $self->{'filehandle'} = $FH;
        }
    }

    ### still no filehandle
    unless(ref $FH eq 'GLOB') {
        return error(
            "No valid filename, binstring or filehandle\n"
        );
    }

    ### the end
    return $self->_decode_loop;
}

sub _decode_loop { #==========================================================

    ### init
    my $self         = shift;
    my $total_length = shift || 0xffffffff;
    my $pID          = shift || 0;
    my $FH           = $self->{'filehandle'};
    my $cfg          = [];

    BYTE:
    while($total_length > 0) {
        my($code, $length, $syminfo, $func_name, $value);

        ### read data header
        unless(read $FH, $code, 1) {
            $self->log->debug("Could not read \$code: $!");
            last BYTE;
        }
        unless(read $FH, $length, 1) {
            $self->log->debug("Could not read \$length: $!");
            last BYTE;
        }

        $code          = unpack("C", $code);
        $length        = unpack("C", $length) or next BYTE;
        $syminfo       = DOCSIS::ConfigFile::Syminfo->from_code($code, $pID);
        $value         = '';
        $total_length -= $length + 2;

        ### nested block
        if($syminfo->func eq 'aggregate') {
            my $aggregate = $self->_decode_loop($length, $syminfo->code);
            push @$cfg, _value_to_cfg($syminfo, $length, undef, $aggregate);
            next BYTE;
        }

        ### normal
        read($FH, my $data, $length);
        my $aggregate;

        ### decode binary string
        if(my $sub = DOCSIS::ConfigFile::Decode->can($syminfo->func)) {
            my $func_name = $syminfo->func;
            ($value, $aggregate) = $sub->($data);
        }
        else {
            my $func_name = "hexstr";
            @{$syminfo}[0,1,3] = ('NA', $code, 'unpack(H*)');
            $value             = DOCSIS::ConfigFile::Decode::hexstr($data);
        }

        ### could not extract data
        unless(defined $value) {
            $self->log->error(
                "Could not decode data with ::Decode->$func_name"
            );
            next BYTE;
        }
 
        ### do something with the result
        push @$cfg, _value_to_cfg($syminfo, $length, $value, $aggregate); 
    }

    ### the end
    return $cfg;
}

sub _value_to_cfg { #=========================================================

    ### init
    my $syminfo   = shift;
    my $length    = shift;
    my $value     = shift;
    my $aggregate = shift;

    ### the end
    return {
        name   => $syminfo->id,
        code   => $syminfo->code,
        pcode  => $syminfo->pcode,
        func   => $syminfo->func,
        llimit => $syminfo->l_limit,
        ulimit => $syminfo->u_limit,
        length => $length,
        (defined $value ? (value     => $value    ) : ()),
        ($aggregate     ? (aggregate => $aggregate) : ()),
    };
}

sub encode { #================================================================

    ### init
    my $self = ref $_[0] ? shift(@_) : shift->new(@_);
    my %args = @_;
    my $config;

    ### setup args
    $self->{$_} = $args{$_} for(keys %args);
    $config     = $self->{'config'};

    ### check config
    unless(ref $config eq 'ARRAY') {
        $self->log->error("Input is not an array ref");
        return;
    }

    ### init cmts mic calculation
    $self->{'cmts_mic_data'}{$_} = [] for(@cmts_mic_list);

    ### encode data
    $self->{'binstring'} = $self->_encode_loop($config);

    ### mta config file
    if(grep { $_->{'name'} eq 'MtaConfigDelimiter' } @$config) {
        $self->log->debug("Setting up MTA config-file");
    }

    ### special cm params
    else {
        $self->log->debug("Setting up CM config-file");

        ### calculate mic, eod and pad
        my $cm_mic   = $self->calculate_cm_mic;
        my $cmts_mic = $self->calculate_cmts_mic($cm_mic);
        my $eod_pad  = $self->calculate_eod_and_pad;

        ### add mic, eod and pad
        $self->{'binstring'} .= $cm_mic .$cmts_mic. $eod_pad;
    }

    ### the end
    return $self->{'binstring'};
}

sub _encode_loop { #==========================================================

    ### init
    my $self      = shift;
    my $config    = shift;
    my $level     = shift || 0;
    my $binstring = '';

    ### check config
    unless(ref $config eq 'ARRAY') {
        $self->log->error("Not an array: " .ref($config) ."\n");
        return "";
    }

    TLV:
    for my $tlv (@$config) {

        ### init
        my $name    = $tlv->{'name'} or next TLV;
        my $syminfo = DOCSIS::ConfigFile::Syminfo->from_id($name);
        my $sub     = DOCSIS::ConfigFile::Encode->can($syminfo->func);
        my $code    = $syminfo->code;

        ### nested tlv
        if($syminfo->func eq 'aggregate') {

            ### set binstring
            my $value   = $self->_encode_loop($tlv->{'aggregate'}, $level+1);
            my $length  = pack "C", length $value;
            my $type    = pack "C", $code;
            $binstring .= $type .$length .$value;

            ### add to cmts mic calculation
            if(!$level and exists $self->{'cmts_mic_data'}{$code}) {
                push @{ $self->{'cmts_mic_data'}{$code} },
                     $type .$length .$value;
            }

            ### skip ahead
            next TLV;
        }

        ### don't know what to do
        elsif(not $sub) {
            $self->log->error("Unknown encode method: $name");
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
        my @value  = $sub->($tlv);
        my $type   = pack "C", $syminfo->code;
        my $length = pack "C", int(@value);
        my $value  = pack "C*", @value;

        ### check value length
        if(length $value > 255) {
            next TLV;
        }

        ### save data to binstring
        $binstring .= "$type$length$value";

        ### add to cmts mic calculation
        if(!$level and exists $self->{'cmts_mic_data'}{$code}) {
            push @{ $self->{'cmts_mic_data'}{$code} },
                 $type .$length .$value;
        }
    }

    ### the end
    return $binstring;
}

sub calculate_eod_and_pad { #=================================================

    ### init
    my $self = shift;
    my $pads = 4 - (1 + length $self->{'binstring'}) % 4;

    ### the end
    return pack("C", 255) .("\0" x $pads);
}

sub calculate_cm_mic { #======================================================

    ### init
    my $self   = shift;
    my $cm_mic = pack("C*", 6, 16) .Digest::MD5::md5($self->{'binstring'});

    ### save to cmts_mic_data
    $self->{'cmts_mic_data'}{6} = [$cm_mic];

    ### the end
    return $cm_mic;
}

sub calculate_cmts_mic { #====================================================

    ### init
    my $self          = shift;
    my $cm_mic        = shift;
    my $shared_secret = $self->{'shared_secret'} || '';
    my $cmts_mic_data = $self->{'cmts_mic_data'};
    my $data          = "";

    ### re-arrage data
    for my $k (@cmts_mic_list) {
        for my $d (@{ $cmts_mic_data->{$k} }) {
            $data .= $d;
        }
    }

    ### the end
    return pack("C*", 7, 16)
          .Digest::HMAC_MD5::hmac_md5($data, $shared_secret)
          ;
}

sub log { #===================================================================
    my $self = shift;
    $self->{'__log'} = shift if(defined $_[0]);
    return $self->{'__log'};
}

sub new { #===================================================================

    ### init
    my $class  = shift;
    my $self   = bless {
                    decoded       => [],
                    filehandle    => '',
                    read_file     => '',
                    binstring     => '',

                    encoded       => '',
                    write_file    => '',
                    shared_secret => '',

                    @_,
                 }, $class;

    ### init logging
    Log::Log4perl->init($LOGCONFIG) unless(Log::Log4perl->initialized);
    $self->log( Log::Log4perl->get_logger($class) );

    ### load mibs
    $ENV{'MIBS'} = (defined $self->{'mibs'}) ? $self->{'mibs'} : 'ALL';

    ### the end
    return $self;
}


#=============================================================================
1983;
__END__

=head1 NAME

DOCSIS::ConfigFile - Decodes and encodes DOCSIS config-files for cable-modems

=head1 VERSION

Version 0.1

=head1 SYNOPSIS

    use DOCSIS::ConfigFile;

    my $obj     = DOCSIS::ConfigFile->new(
                      filehandle => $glob,
                      read_file  => $filename,
                      binstring  => $data,

                      config        => $decoded,
                      shared_secret => '',
                  );
    my $decoded = $obj->decode;
    my $encoded = $obj->encode;
 
=head1 METHODS

=head2 new

Object constructor. Takes any of the arguments C<decode> or C<encode> takes.

=head2 decode

Decodes the config-file. Constructor needs only one of these arguments:

 * filehandle => reference to an open file.
 * read_file  => path to a file to read.
 * binstring  => a string containing the binary config.

Returns:

 * On error: undef.
 * On success: an array of hashes containing the config.

=head2 encode

Encodes the config-file settings. Arguments to pass on to the constructor:

 * config        => array of hashes reference.
 * shared_secret => a string containing the shared secret to match in the
                    CMTS.

Returns:
 
 * On error: undef
 * On success: a binary string

=head2 log

Returns a log-handler. Log::Log4perl by default.

=head2 calculate_eod_and_pad

Returns the EOD and padding for the config-file. Called automatically from
inside encode().

=head2 calculate_cm_mic

Returns the CM MIC. Called automatically from inside encode().

=head2 calculate_cmts_mic

Returns the CMTS MIC. Called automatically from inside encode().

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

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/DOCSIS-ConfigFile>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/DOCSIS-ConfigFile>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=DOCSIS-ConfigFile>

=item * Search CPAN

L<http://search.cpan.org/dist/DOCSIS-ConfigFile>

=back

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
