
#==================================
package DOCSIS::ConfigFile::Decode;
#==================================

use strict;
use warnings;
use bytes;
use Math::BigInt;
use Socket;
use constant syminfo => "DOCSIS::ConfigFile::Syminfo";

our $ERROR     = q();
our %SNMP_TYPE = (
    0x02 => [ 'INTEGER',    \&uint   ],
    0x04 => [ 'STRING',     \&string ],
    0x05 => [ 'NULLOBJ',    sub {}   ],
    0x40 => [ 'IPADDRESS',  \&ip     ],
    0x41 => [ 'COUNTER',    \&uint   ],
    0x42 => [ 'UNSIGNED',   \&uint   ],
    0x43 => [ 'TIMETICKS',  \&uint   ],
    0x44 => [ 'OPAQUE',     \&uint   ],
    0x46 => [ 'COUNTER64',  \&bigint ],
);


sub snmp_type { #=============================================================
    return $SNMP_TYPE{lc shift} || $SNMP_TYPE{4};
}

sub snmp_oid { #==============================================================

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

    return join ".", @decoded_oid;
}

sub snmp_object { #===========================================================

    my $bin_string     = shift;
    my @data           = unpack "C*", $bin_string;
    my $seq_id         = shift @data;
    my $message_length = shift @data;
    my $obj_id         = shift @data;
    my $oid_length     = shift @data;
    my $oid            = snmp_oid(splice @data, 0, $oid_length);
    my $value_type     = shift @data;
    my $value_length   = shift @data;
    my $type           = snmp_type($value_type);
    my $bin_value      = substr $bin_string, 6 + $oid_length;
    my $value          = $type->[1]->($bin_value);

    ### check value
    return {} unless(defined $value);

    return {
        oid   => $oid,
        type  => $type->[0],
        value => $value,
    };
}

sub bigint { #================================================================

    my @bytes = unpack 'C*', shift;
    my $value = ($bytes[0] & 0x80) ? -1 : shift @bytes;
    my $int64 = Math::BigInt->new($value);

    ### setup int64
    for(@bytes) {
        $_     ^= 0xff if($value < 0);
        $int64  = ($value << 8) | $_;
    }

    return $int64;
}

sub uint { #==================================================================

    my @bytes  = unpack 'C*', shift;
    my $length = @bytes;
    my $size   = syminfo->byte_size('int');
    my $value  = ($bytes[0] & 0x80) ? -1 : 0;

    ### check
    if($length > $size) {
        $ERROR = "length mismatch: $length > $size";
        return;
    }

    $value = ($value << 8) | $_ for(@bytes);
    return $value;
}

sub ushort { #================================================================

    my $bin    = shift;
    my $length = length $bin;
    my $size   = syminfo->byte_size('short int');

    ### check
    if($length > $size) {
        $ERROR = "length mismatch: $length > $size";
        return;
    }

    return unpack('n', $bin);
}

sub uchar { #=================================================================
    return join "", unpack('C', shift);
}

sub vendorspec { #============================================================

    my $bin = shift;
    my($vendor, @ret, $length);

    $bin    =~ s/.(.)// or return; # remove the two first bytes
    $length =  unpack "C*", $1;

    ### find vendor
    if($bin =~ s/(.{$length})//) {
        my $f   = "%02x" x $length;
        $vendor = sprintf "0x$f", unpack "C*", $1;
    }

    while($bin =~ s/^(.)(.)//) {
        my $type   = unpack "C*", $1;
        my $length = unpack "C*", $2;

        if($bin =~ s/(.{$length})//) {
            push @ret, {
                type   => $type,
                length => $length,
                value  => hexstr($1),
            };
        }
    }

    return $vendor, \@ret;
}

sub ip { #====================================================================

    my $bin     = shift;
    my $address = inet_ntoa($bin);

    ### check
    unless($address) {
        $ERROR = "Invalid IP address";
        return;
    }

    return $address;
}

sub ether { #=================================================================

    my $bin    = shift;
    my $length = length $bin;

    ### check
    unless($length == 6 or $length == 12) {
        $ERROR = "Invalid MAC address";
        return;
    }

    return join ":", unpack("H2" x $length, $bin);
}

sub string { #================================================================

    my $bin = shift;

    ### hex string
    if($bin =~ /[\x00-\x1f\x7f-\xff]/) {
        return hexstr($bin);
    }

    ### normal string
    else {
        return sprintf "%s", $bin;
    }
}

sub hexstr { #================================================================
    return "0x" .join("", unpack "H*", shift);
}

sub mic { #===================================================================
    return hexstr(@_);
}

#=============================================================================
1983;
__END__

=head1 NAME

DOCSIS::ConfigFile::Decode - Decode functions for a DOCSIS config-file

=head1 VERSION

See DOCSIS::ConfigFile

=head1 FUNCTIONS

=head2 snmp_type(lc $arg)

Returns an array-ref to an array with two elements:

 1) The string of the SNMP type.
 2) A reference to the function to decode the value.

=head2 snmp_oid(@bytes)

Returns a numeric OID.

=head2 snmp_object($bytestring)

Returns a hash-ref:

 {
   oid   => "", # numeric OID
   type  => "", # what kind of value (corresponding to C<snmp_type>)
   value => "", # the oid value
 }

=head2 bigint($bytestring)

Returns a C<Math::BigInt> object.

=head2 uint($bytestring)

Returns an unsigned integer: 0..2**32-1

=head2 ushort($bytestring)

Returns an unsigned short integer: 0..2**16-1

=head2 uchar($bytesstring)

Returns an unsigned character: 0..2**8-1

=head2 vendorspec($bytestring)

Returns a list containing ($vendor, \%nested).

Example:

  "0x001337", # vendors ID
  {
    type   => "24", # vendor specific type
    value  => "42", # vendor specific value
    length => "1",  # the length of the value meassured in bytes
  },


=head2 ip($bytestring)

Returns an IPv4-address.

=head2 ether($bytestring)

Returns a MAC-address.

=head2 string($bytestring)

Returns human-readable string if it can, or the string hex-encoded if it
cannot.

=head2 hexstr($bytestring)

Returns a value, printed as hex.

=head2 mic($bytestring)

Returns a value, printed as hex.

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
