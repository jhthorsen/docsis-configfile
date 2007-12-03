
#==================================
package DOCSIS::ConfigFile::Encode;
#==================================

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
__END__

=head1 NAME DOCSIS::ConfigFile::Encode

=head1 VERSION

See DOCSIS::ConfigFile

=head1 FUNCTIONS

=head2 byte_size

=head2 snmp_type

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

=head2 strzero

=head2 hexstr

=head2 int_to_bytes

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

------------------------------------------------------------------------------
THIS PROGRAM IS BASED ON THE C-PROGRAM "docsis" FROM docsis.sf.net!
------------------------------------------------------------------------------

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

=cut
