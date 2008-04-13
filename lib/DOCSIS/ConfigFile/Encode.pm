
#==================================
package DOCSIS::ConfigFile::Encode;
#==================================

use strict;
use warnings;
use bytes;
use Math::BigInt;
use Socket;

our $ERROR     = q();
our %SNMP_TYPE = (
    INTEGER   => [ 0x02, \&uint   ],
    STRING    => [ 0x04, \&string ],
    NULLOBJ   => [ 0x05, sub {}   ],
    IPADDRESS => [ 0x40, \&ip     ],
    COUNTER   => [ 0x41, \&uint   ],
    UNSIGNED  => [ 0x42, \&uint   ],
    TIMETICKS => [ 0x43, \&uint   ],
    OPAQUE    => [ 0x44, \&uint   ],
    COUNTER64 => [ 0x46, \&bigint ],
);


sub snmp_type { #=============================================================
    return $SNMP_TYPE{uc shift} || $SNMP_TYPE{'STRING'};
}

sub snmp_oid { #==============================================================

    ### init
    my $string    = shift or return;
    my @input_oid = split /\./, $string;
    my $subid     = 0;
    my @encoded_oid;

    ### the first two sub-id are in the first id
    {
        my $first  = shift @input_oid;
        my $second = shift @input_oid;
        push @encoded_oid, $first * 40 + $second;
    }

    SUB_OID:
    for my $id (@input_oid) {
        if($id <= 0x7f) {
            push @encoded_oid, $id;
        }
        else {
            my @suboid;
            while($id) {
                unshift @suboid, 0x80 | ($id & 0x7f);
                $id >>= 7;
            }
            $suboid[-1] &= 0x7f;
            push @encoded_oid, @suboid;
        }
    }

    ### the end
    return wantarray ? @encoded_oid : \@encoded_oid;
}

sub snmp_object { #===========================================================

    ### init
    my $obj    = shift->{'value'} or return;
    my @oid    = snmp_oid($obj->{'oid'});
    my $type   = snmp_type($obj->{'type'});
    my @value  = $type->[1]->({ value => $obj->{'value'}, snmp => 1 });
    my $length = int(@oid) + int(@value) + 4;
    
    my @ret = (
      #-type--------length-------value-----type---
        48,         $length,             # object
        6,          int(@oid),   @oid,   # oid
        $type->[0], int(@value), @value, # value
    );

    ### the end
    return wantarray ? @ret : \@ret;
}

sub bigint { #================================================================

    ### init
    my $int64    = Math::BigInt->new(shift()->{'value'});
    my $negative = $int64 < 0;
    my @bytes    = $negative ? (0x80) : ();

    while($int64) {
        my $value  = $int64 & 0xff;
        $int64   >>= 8;
        $value    ^= 0xff if($negative);
        unshift @bytes, $value;
    }

    ### bytes need a value
    @bytes = (0) unless(@bytes);

    ### the end
    return wantarray ? @bytes : \@bytes;
}

sub uint { #==================================================================

    ### init
    my $obj      = shift;
    my $int      = $obj->{'value'} || 0;
    my $negative = $int < 0;
    my @bytes;


    while($int) {
        my $value  = $int & 0xff;
        $int     >>= 8;
        $value    ^= 0xff if($negative);
        unshift @bytes, $value;
    }

    ### fix bytes
    unless($obj->{'snmp'}) {
        $bytes[0] |= 0x80 if($negative);
        unshift @bytes, 0 for(1..4-@bytes);
    }
    unless(@bytes) {
        @bytes = (0);
    }

    ### set positive
    if($obj->{'snmp'}) {
        unshift @bytes, 0 if(!$negative and $bytes[0] > 0x79);
    }

    ### the end
    return wantarray ? @bytes : \@bytes;
}

sub ushort { #================================================================

    ### init
    my $obj      = shift;
    my $short    = $obj->{'value'};
    my $negative = $short < 0;
    my @bytes;

    ### set positive
    if($obj->{'snmp'}) {
        unshift @bytes, 0 if(!$negative and $short > 0x79);
    }

    while($short) {
        my $value  = $short & 0xff;
        $short   >>= 8;
        $value    ^= 0xff if($negative);
        unshift @bytes, $value;
    }

    ### fix bytes
    unless($obj->{'snmp'}) {
        $bytes[0] |= 0x80 if($negative);
        unshift @bytes, 0 for(1..2-@bytes);
    }

    ### bytes need a value
    @bytes = (0) unless(@bytes);

    ### the end
    return wantarray ? @bytes : \@bytes;
}

sub uchar { #=================================================================
    my $value = 0xff & shift->{'value'};
    return wantarray ? ($value) : [$value];
}

sub vendorspec { #============================================================

    ### init
    my $obj    = shift;
    my $nested = $obj->{'nested'};
    my(@vendor, @bytes);

    ### check
    return unless(ref $nested eq 'ARRAY');

    @vendor = ether($obj);
    @bytes  = (8, int(@vendor), @vendor);

    TLV:
    for my $tlv (@$nested) {
        push @bytes, $tlv->{'type'};
        push @bytes, $tlv->{'length'};
        push @bytes, ether($tlv);
    }

    ### the end
    return wantarray ? @bytes : \@bytes;
}

sub ip { #====================================================================
    my @value = split /\./, shift->{'value'};
    return wantarray ? @value : [@value];
}

sub ether { #=================================================================

    ### init
    my $obj    = shift or return;
    my $string = $obj->{'value'};

    return unless(defined $string);

    ### numeric
    if($string =~ /^\d+$/) {
        return value_to_bytes({ int => $string });
    }

    ### hex
    elsif($string =~ /^(?:0x)?([0-9a-f]+)$/i) {
        return value_to_bytes({ hex => $1 });
    }
}

sub oid { #===================================================================
    return snmp_oid(shift->{'value'});
}

sub string { #================================================================

    ### init
    my $obj    = shift;
    my $string = $obj->{'value'};

    ### hex
    if($string =~ /^0x([0-9a-f]+)$/i) {
        return value_to_bytes({ hex => $1 });
    }

    ### normal
    else {
        my @ret = map { ord $_ } split //, $string;
        return wantarray ? @ret : \@ret;
    }
}

sub hexstr { #================================================================

    ### init
    my $ether = shift->{'value'};

    ### numeric
    if($ether =~ /^\d+$/) {
        return value_to_bytes({ int => $ether });
    }

    ### hex
    elsif($ether =~ /^(?:0x)?([0-9a-f]+)$/i) {
        return value_to_bytes({ hex => $1 });
    }
}

sub value_to_bytes { #========================================================

    ### init
    my $data = shift || {};
    my($value, @bytes);

    ### from hex
    if($value = $data->{'hex'}) {

        return unless($value =~ /^[0-9a-fA-F]+$/);

        while($value) {
            $value =~ s/(\w{1,2})$//;
            unshift @bytes, hex $1;
        }
    }

    ### from int
    elsif($value = $data->{'int'}) {

        return unless($value =~ /^\d+$/);

        while($value) {
            my $v    = $value & 0xff;
            $value >>= 8;
            unshift @bytes, $v;
        }
    }

    ### the end
    return wantarray ? @bytes : \@bytes;
}

sub mic { #===================================================================
    return;
}

#=============================================================================
1983;
__END__

=head1 NAME

DOCSIS::ConfigFile::Encode - Encode functions for a DOCSIS config-file.

=head1 VERSION

See DOCSIS::ConfigFile

=head1 FUNCTIONS

=head2 snmp_type($arg)

Returns an array-ref to an array with two elements:

 1) The numeric value of the SNMP type.
 2) A reference to the function to encode the value.

=head2 snmp_oid

=head2 snmp_object

=head2 bigint

=head2 uint

=head2 ushort

=head2 ushort_list

=head2 uchar

=head2 vendorspec

=head2 ip

=head2 ether

=head2 oid

=head2 string

=head2 hexstr

=head2 value_to_bytes

=head2 mic

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
