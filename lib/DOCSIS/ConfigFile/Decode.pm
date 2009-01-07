package DOCSIS::ConfigFile::Decode;

=head1 NAME

DOCSIS::ConfigFile::Decode - Decode functions for a DOCSIS config-file

=head1 VERSION

See DOCSIS::ConfigFile

=cut

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

=head1 FUNCTIONS

=head2 snmp_type(lc $arg)

Returns an array-ref to an array with two elements:

 1) The string of the SNMP type.
 2) A reference to the function to decode the value.

=cut

sub snmp_type {
    return $SNMP_TYPE{lc shift} || $SNMP_TYPE{4};
}

=head2 snmp_oid(@bytes)

Returns a numeric OID.

=head2 snmp_object($bytestring)

Returns a hash-ref:

 {
   oid   => "", # numeric OID
   type  => "", # what kind of value (corresponding to C<snmp_type>)
   value => "", # the oid value
 }

=cut

sub snmp_oid {
    my @input_oid   = @_;
    my @decoded_oid = (0);
    my $subid       = 0;

    OID:
    for my $id (@input_oid) {
        return if($subid & 0xfe000000); # sub-identifier too large

        $subid = ($subid << 7) | ($id & 0x7f);

        unless($id & 0x80) {
            return if(@decoded_oid == 127); # exceeded max length
            push @decoded_oid, $subid;
            $subid = 0;
        }
    }

    # the first two sub-id are in the first id
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

sub snmp_object {
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

    return {} unless(defined $value);

    return {
        oid   => $oid,
        type  => $type->[0],
        value => $value,
    };
}

=head2 bigint($bytestring)

Returns a C<Math::BigInt> object.

=cut

sub bigint {
    my @bytes = unpack 'C*', shift;
    my $value = ($bytes[0] & 0x80) ? -1 : shift @bytes;
    my $int64 = Math::BigInt->new($value);

    # setup int64
    for(@bytes) {
        $_     ^= 0xff if($value < 0);
        $int64  = ($value << 8) | $_;
    }

    return $int64;
}

=head2 uint($bytestring)

Returns an unsigned integer: 0..2**32-1

=cut

sub uint {
    my @bytes  = unpack 'C*', shift;
    my $length = @bytes;
    my $size   = syminfo->byte_size('int');
    my $value  = ($bytes[0] & 0x80) ? -1 : 0;

    if($length > $size) {
        $ERROR = "length mismatch: $length > $size";
        return;
    }

    $value = ($value << 8) | $_ for(@bytes);

    return $value;
}

=head2 ushort($bytestring)

Returns an unsigned short integer: 0..2**16-1

=cut

sub ushort {
    my $bin    = shift;
    my $length = length $bin;
    my $size   = syminfo->byte_size('short int');

    if($length > $size) {
        $ERROR = "length mismatch: $length > $size";
        return;
    }

    return unpack('n', $bin);
}

=head2 uchar($bytesstring)

Returns an unsigned character: 0..2**8-1

=cut

sub uchar {
    return join "", unpack('C', shift);
}

=head2 vendorspec($bytestring)

Returns a list containing ($vendor, \%nested).

Example:

  "0x001337", # vendors ID
  {
    type   => "24", # vendor specific type
    value  => "42", # vendor specific value
    length => "1",  # the length of the value meassured in bytes
  },

=cut

sub vendorspec {
    my $bin = shift;
    my($vendor, @ret, $length);

    $bin    =~ s/.(.)// or return; # remove the two first bytes
    $length =  unpack "C*", $1;

    if($bin =~ s/(.{$length})//) { # find vendor
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

=head2 ip($bytestring)

Returns an IPv4-address.

=cut

sub ip {
    my $bin     = shift;
    my $address = inet_ntoa($bin);

    unless($address) {
        $ERROR = "Invalid IP address";
        return;
    }

    return $address;
}

=head2 ether($bytestring)

Returns a MAC-address.

=cut

sub ether {
    my $bin    = shift;
    my $length = length $bin;

    unless($length == 6 or $length == 12) {
        $ERROR = "Invalid MAC address";
        return;
    }

    return join ":", unpack("H2" x $length, $bin);
}

=head2 string($bytestring)

Returns human-readable string if it can, or the string hex-encoded if it
cannot.

=cut

sub string {
    my $bin = shift;

    if($bin =~ /[\x00-\x1f\x7f-\xff]/) { # hex string
        return hexstr($bin);
    }
    else { # normal string
        return sprintf "%s", $bin;
    }
}

=head2 hexstr($bytestring)

Returns a value, printed as hex.

=cut

sub hexstr {
    return "0x" .join("", unpack "H*", shift);
}

=head2 mic($bytestring)

Returns a value, printed as hex.

=cut

sub mic {
    return hexstr(@_);
}

=head1 AUTHOR

=head1 BUGS

=head1 SUPPORT

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

See L<DOCSIS::ConfigFile>

=cut

1;
