
#======================
package DOCSIS::Encode;
#======================

#  DOCSIS configuration file encoder.
#  Copyright (c) 2001 Cornel Ciocirlan, ctrl@users.sourceforge.net.
#  Copyright (c) 2002,2003,2004 Evvolve Media SRL,office@evvolve.com
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#  DOCSIS is a registered trademark of Cablelabs, http://www.cablelabs.com

use strict;
use warnings;
use bytes;
use Socket;

our $ERROR     = '';
our %SNMP_TYPE = (
                     'INTEGER'   => [ 0x02, \&uint   ],
                     'STRING'    => [ 0x04, \&string ],
                     'NULLOBJ'   => [ 0x05, sub {}   ],
                     'IPADDRESS' => [ 0x40, \&ip     ],
                     'COUNTER'   => [ 0x41, \&uint   ],
                     'UNSIGNED'  => [ 0x42, \&uint   ],
                     'TIMETICKS' => [ 0x43, \&uint   ],
                     'OPAQUE'    => [ 0x44, \&uint   ],
                     'COUNTER64' => [ 0x46, \&bigint ],
                 );


sub byte_size { #=============================================================
    return $DOCSIS::Perl::BYTE_SIZE{lc shift} || 0;
}

sub snmp_type { #=============================================================
    return $SNMP_TYPE{uc shift} || $SNMP_TYPE{'STRING'};
}

sub snmp_oid { #==============================================================

    ### init
    my @input_oid = split /\./, shift;
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
    return @encoded_oid;
}

sub snmp_object { #===========================================================

    ### init
    my $obj   = shift()->{'value'};
    my @oid   = snmp_oid($obj->{'oid'});
    my $type  = snmp_type($obj->{'type'});
    my @value = $type->[1]->({ value => $obj->{'value'}, snmp => 1 });

    ### the end
    return 48,
           int(@oid) + int(@value) + 4,
           6,
           int(@oid),   @oid,
           $type->[0],
           int(@value), @value,
           ;
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

    ### the end
    return @bytes || (0);
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
    return @bytes;
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

    ### the end
    @bytes = (0) unless(@bytes);
    return @bytes;
}

sub ushort_list { #===========================================================
}

sub uchar { #=================================================================
    return 0xff & shift()->{'value'};
}

sub vendorspec { #============================================================

    ### init
    my $obj       = shift;
    my @vendor    = map { hex $_ } ($obj->{'value'} =~ /(\w{2})/g);
    my $aggregate = $obj->{'aggregate'};
    my @bytes;

    ### check
    return unless(ref $aggregate eq 'ARRAY');

    TLV:
    for my $tlv (@$aggregate) {
        push @bytes, $tlv->{'type'};
        push @bytes, $tlv->{'length'};
        push @bytes, $tlv->{'value'};
    }

    ### the end
    return 8, 3, @vendor, @bytes;
}

sub ip { #====================================================================
    return split /\./, shift()->{'value'};
}

sub ether { #=================================================================

    ### init
    my $string = shift()->{'value'};

    ### numeric
    if($string =~ /^\d+$/) {
        return int_to_bytes({ value => $string });
    }

    ### hex
    elsif($string =~ /^(?:0x)?[0-9a-f]+$/i) {
        return int_to_bytes({ value => hex($string) });
    }
}

sub oid { #===================================================================
    return snmp_oid(shift()->{'value'});
}

sub string { #================================================================

    ### init
    my $string = shift()->{'value'};

    ### hex
    if($string =~ /^0x[0-9a-f]+$/i) {
        return int_to_bytes({ value => hex($string) });
    }

    ### normal
    else {
        return map { ord $_ } split //, $string;
    }
}

sub strzero { #===============================================================
    uchar(@_);
}

sub hexstr { #================================================================

    ### init
    my $ether = shift()->{'value'};

    ### numeric
    if($ether =~ /^\d+$/) {
        return int_to_bytes({ value => $ether });
    }

    ### hex
    elsif($ether =~ /^(?:0x)?[0-9a-f]+$/i) {
        return int_to_bytes({ value => hex($ether) });
    }
}

sub int_to_bytes { #==========================================================

    ### init
    my $string = shift()->{'value'};
    my @bytes;

    while($string) {
        my $value = $string & 0xff;
        $string >>= 8;
        unshift @bytes, $value;
    }

    ### the end
    return @bytes;
}

#=============================================================================
1983;
