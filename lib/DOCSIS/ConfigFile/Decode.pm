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
    0x02 => [ 'INTEGER',    \&uint        ],
    0x04 => [ 'STRING',     \&string,     ],
    0x05 => [ 'NULLOBJ',    sub {}        ],
    0x40 => [ 'IPADDRESS',  \&ip          ],
    0x41 => [ 'COUNTER',    \&uint        ],
    0x42 => [ 'UNSIGNED',   \&uint        ],
    0x43 => [ 'TIMETICKS',  \&uint        ],
    0x44 => [ 'OPAQUE',     \&uint        ],
    0x46 => [ 'COUNTER64',  \&bigint      ],
);

=head1 FUNCTIONS

=head2 snmp_object

 $data = snmp_object($bytestring);

C<$data> template:

 {
   oid   => "", # numeric OID
   type  => "", # what kind of value (corresponding to C<snmp_type>)
   value => "", # the oid value
 }

=cut

sub snmp_object {
    my $data = shift;
    my($byte, $length, $oid, $type, $value);

    # message
    _chop(\$data, "C1"); # 0x30
    $byte   = _chop(\$data, "C1"); # length?
    $length = $byte == 0x81 ? _chop(\$data, "C1")
            : $byte == 0x82 ? _chop(\$data, "n1")
            :                 $byte;

    # oid
    _chop(\$data, "C1"); # 0x06
    $length = _chop(\$data, "C1");
    $oid    = _snmp_oid( _chop(\$data, "C$length") );

    # value
    $type   = $SNMP_TYPE{ _chop(\$data, "C1") };
    $length = $byte == 0x82 ? _chop(\$data, "S1")
            :                 _chop(\$data, "C1");
    $value  = $type->[1]->($data);

    return {
        oid   => $oid,
        type  => $type->[0],
        value => $value,
    };
}

sub _snmp_oid {
    my @bytes  = @_;
    my @oid    = (0);
    my $subid  = 0;

    for my $id (@bytes) {
        if($subid & 0xfe000000) {
            $@ = q(Sub-identifier too large);
            return;
        }

        $subid = ($subid << 7) | ($id & 0x7f);

        unless($id & 0x80) {
            if(128 <= @oid) {
                $@ = q(Exceeded max length);
                return;
            }

            push @oid, $subid;
            $subid = 0;
        }
    }

    # the first two sub-id are in the first id
    if($oid[1] == 0x2b) {   # Handle the most common case
        $oid[0] = 1;
        $oid[1] = 3;
    }
    elsif($oid[1] < 40) {
        $oid[0] = 0;
    }
    elsif($oid[1] < 80) {
        $oid[0]  = 1;
        $oid[1] -= 40;
    }
    else {
        $oid[0]  = 2;
        $oid[1] -= 80;
    }

    return join ".", @oid;
}

sub _chop {
    my $str  = shift;
    my $type = shift;
    my $n    = ($type =~ /C/ ? 1 : 2) * ($type =~ /(\d+)/)[0];

    return unpack $type, $1 if($$str =~ s/^(.{$n})//s);
    return;
}

=head2 bigint

 $bigint_obj = bigint($bytestring);

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

=head2 uint

 $int = uint($bytestring);

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

=head2 ushort

 $short = ushort($bytestring);

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

=head2 uchar

 $chr = uchar($bytesstring);

Returns an unsigned character: [0..255]

=cut

sub uchar {
    return join "", unpack('C', shift);
}

=head2 vendorspec

 ($vendor_id, $vendor_data) = vendorspec($bytestring);

Return value example:

  "0x001337" => { # vendor ID
    type   => "24", # vendor specific type
    value  => "42", # vendor specific value
    length => "1",  # the length of the value meassured in bytes
  };

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

=head2 ip

 $ipv4_address = ip($bytestring);

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

=head2 ether

 $mac = ether($bytestring);

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
    my $bin = @_ > 1 ? join("", map { chr $_ } @_) : $_[0];

    if($bin =~ /[^\t\n\r\x20-\xef]/) { # hex string
        return hexstr($bin);
    }
    else { # normal string
        $bin =~ s/\x00//g;
        $bin =~ s/([^\t\n\x20-\x7e])/{ sprintf "%%%02x", ord $1 }/ge;
        return $bin;
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
