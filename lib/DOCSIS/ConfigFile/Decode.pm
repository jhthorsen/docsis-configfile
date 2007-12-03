
#==================================
package DOCSIS::ConfigFile::Decode;
#==================================

use strict;
use warnings;
use bytes;
use Socket;

our $ERROR     = '';
our %SNMP_TYPE = (
                    0x02 => [ 'INTEGER',        \&uint   ],
                    0x04 => [ 'STRING',         \&string ],
                    0x05 => [ 'NULLOBJ',        sub {}   ],
                    0x40 => [ 'IPADDRESS',      \&ip     ],
                    0x41 => [ 'COUNTER',        \&uint   ],
                    0x42 => [ 'UNSIGNED',       \&uint   ],
                    0x43 => [ 'TIMETICKS',      \&uint   ],
                    0x44 => [ 'OPAQUE',         \&uint   ],
                    0x46 => [ 'COUNTER64',      \&bigint ],
                );


sub byte_size { #=============================================================
    return $DOCSIS::ConfigFile::BYTE_SIZE{lc shift} || 0;
}

sub snmp_type { #=============================================================
    return $SNMP_TYPE{lc shift} || $SNMP_TYPE{4};
}

sub snmp_oid { #==============================================================

    ### init
    my @input_oid   = @_;
    my @decoded_oid = (0);
    my $subid       = 0;

    ### fix oid
    for my $id (@input_oid) {

        ### sub-identifier too large
        return if($subid & 0xfe000000);

        $subid = ($subid << 7) | ($id & 0x7f);

        unless($id & 0x80) {

            ### exceeded max length
            return if(@decoded_oid == 127);

            ### oid is ok
            push @decoded_oid, $subid;
            $subid = 0;
        }
    }

    ### the first two sub-id are in the first id
    if($decoded_oid[1] == 0x2b) {   # Handle the most common case
        $decoded_oid[0] = 1;        # first [iso(1).org(3)]
        $decoded_oid[1] = 3;
    }
    elsif($decoded_oid[1] < 40) {
        $decoded_oid[0] = 0;
    }
    elsif($decoded_oid[1] < 80) {
        $decoded_oid[0]  = 1;
        $decoded_oid[1] -= 40;
    }
    else {
        $decoded_oid[0]  = 2;
        $decoded_oid[1] -= 80;
    }

    ### the end
    return join ".", @decoded_oid;
}

sub snmp_object { #===========================================================

    ### init
    my $bin_string     = shift;
    my @data           = unpack "C*", $bin_string;
    my $seq_id         = shift  @data;
    my $message_length = shift  @data;
    my $obj_id         = shift  @data;
    my $oid_length     = shift  @data;
    my $oid            = snmp_oid(splice @data, 0, $oid_length);
    my $value_type     = shift  @data;
    my $value_length   = shift  @data;
    my $type           = snmp_type($value_type);
    my $bin_value      = substr $bin_string, 6 + $oid_length;
    my $value          = $type->[1]->($bin_value);

    ### check value
    return {} unless(defined $value);

    ### the end
    return {
        oid   => $oid,
        type  => $type->[0],
        value => $value,
    };
}

sub bigint { #================================================================

    ### init
    my @bytes = unpack 'C*', shift;
    my $value = ($bytes[0] & 0x80) ? -1 : shift @bytes;
    my $int64 = Math::BigInt->new($value);

    ### setup int64
    for(@bytes) {
        $_     ^= 0xff if($value < 0);
        $int64  = ($value << 8) | $_;
    }

    ### the end
    return $int64;
}

sub uint { #==================================================================

    ### init
    my @bytes  = unpack 'C*', shift;
    my $length = @bytes;
    my $size   = byte_size('int');
    my $value  = ($bytes[0] & 0x80) ? -1 : 0;

    ### check
    if($length > $size) {
        $ERROR = "length mismatch: $length > $size";
        return;
    }

    ### the end
    $value = ($value << 8) | $_ for(@bytes);
    return $value;
}

sub ushort { #================================================================

    ### init
    my $bin    = shift;
    my $length = length $bin;
    my $size   = byte_size('short int');

    ### check
    if($length > $size) {
        $ERROR = "length mismatch: $length > $size";
        return;
    }

    ### the end
    return unpack('n', $bin);
}

sub ushort_list { #===========================================================
}

sub uchar { #=================================================================
    return join "", unpack('C', shift);
}

sub vendorspec { #============================================================

    ### init
    my $bin    = shift;
    my @input  = unpack "C*", $bin;
    my $vendor = sprintf "%02x%02x%02x", @input[2..4];
    my @data   = @input[5..$#input];
    my @ret;

    while(@data) {
        my $type   = shift  @data;
        my $length = shift  @data;
        my $value  = splice @data, 0, $length;
        push @ret, {
            type   => $type,
            length => $length,
            value  => $value,
        };
    }

    ### the end
    return $vendor, \@ret;
}

sub ip { #====================================================================

    ### init
    my $bin     = shift;
    my $address = inet_ntoa($bin);

    ### check
    unless($address) {
        $ERROR = "Invalid IP address";
        return;
    }

    ### the end
    return $address;
}

sub ether { #=================================================================

    ### init
    my $bin    = shift;
    my $length = length $bin;

    ### check
    unless($length == 6 or $length == 12) {
        $ERROR = "Invalid MAC address";
        return;
    }

    ### the end
    return join ":", unpack("H2" x $length, $bin);
}

sub oid { #===================================================================
    return snmp_oid(shift);
}

sub string { #================================================================

    ### init
    my $bin = shift;

    ### hex string
    if($bin =~ /[\x00-\x1f\x7f-\xff]/) {
        return "0x" .hexstr($bin);
    }

    ### normal string
    else {
        return sprintf "%s", $bin;
    }
}

sub strzero { #===============================================================
    return sprintf "%s", shift;
}

sub hexstr { #================================================================
    return join "", unpack "H*", shift;
}

#=============================================================================
1983;
__END__

=head1 NAME DOCSIS::ConfigFile::Decode

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
