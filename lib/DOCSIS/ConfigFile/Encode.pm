package DOCSIS::ConfigFile::Encode;

=head1 NAME

DOCSIS::ConfigFile::Encode - Encode functions for a DOCSIS config-file.

=head1 VERSION

See DOCSIS::ConfigFile

=cut

use strict;
use warnings;
use bytes;
use Math::BigInt;
use Socket;

our $ERROR     = q();
our %SNMP_TYPE = (
    INTEGER   => [ 0x02, \&uint        ],
    STRING    => [ 0x04, \&string      ],
    NULLOBJ   => [ 0x05, sub {}        ],
    IPADDRESS => [ 0x40, \&ip          ],
    COUNTER   => [ 0x41, \&uint        ],
    UNSIGNED  => [ 0x42, \&uint        ],
    TIMETICKS => [ 0x43, \&uint        ],
    OPAQUE    => [ 0x44, \&uint        ],
    COUNTER64 => [ 0x46, \&bigint      ],
);

=head1 FUNCTIONS

Every function can return either a list or an array-ref.

=head2 snmp_object(\%h)

Takes a hash-ref (keys: oid, type, value), and returns a byte-encoded snmp-
object.

 #-type---length---------value-----type---
   48,    $total_length,         # object
   6,     int(@oid),     @oid,   # oid
   $type, int(@value),   @value, # value

=cut

sub snmp_object {
    my $obj    = shift->{'value'}           or return;
    my @oid    = _snmp_oid($obj->{'oid'})   or return;
    my $type   = $SNMP_TYPE{$obj->{'type'}} or return;
    my @value  = $type->[1]->({ value => $obj->{'value'}, snmp => 1 });
    my(@total_length, @value_length);

    return unless(@value);

    @value_length = (0 + @value);

    while(255 <= $value_length[0]) {
        push @value_length, $value_length[0] && 255;
        $value_length[0] >>= 8;
    }

    @total_length = (@value + @oid + @value_length + 2);

    if($total_length[0] >= 0x80) {
        if($total_length[0] < 0xff) {
            $total_length[1] = $total_length[0];
            $total_length[0] = 0x81;
        }
        elsif($total_length[0] < 0xffff) {
            push @total_length, unpack "C2", pack "n", $total_length[0];
            $total_length[0] = 0x82;
        }
    }

    my @ret = (
      #-type--------length----------value-----type---
        0x30,       @total_length,          # object
        0x06,       int(@oid),      @oid,   # oid
        $type->[0], @value_length,  @value, # value
    );

    return wantarray ? @ret : \@ret;
}

sub _snmp_oid {
    my $string    = shift or return;
    my @input_oid = split /\./, $string;
    my $subid     = 0;
    my @encoded_oid;

    # the first two sub-id are in the first id
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

    return wantarray ? @encoded_oid : \@encoded_oid;
}

=head2 bigint(\%h)

Takes a hash-ref, and byte-encodes C<$h-E<gt>{'value'}>. The value could be any
number.

=cut

sub bigint {
    my $int64    = Math::BigInt->new(shift->{'value'});
    my $negative = $int64 < 0;
    my @bytes    = $negative ? (0x80) : ();

    while($int64) {
        my $value  = $int64 & 0xff;
        $int64   >>= 8;
        $value    ^= 0xff if($negative);
        unshift @bytes, $value;
    }

    @bytes = (0) unless(@bytes); # bytes need a value

    return wantarray ? @bytes : \@bytes;
}

=head2 uint(\%h)

Takes a hash-ref, and byte-encodes C<$h-E<gt>{'value'}>. The value has to be an
unsigned int.

=cut

sub uint {
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

    unless($obj->{'snmp'}) {
        $bytes[0] |= 0x80 if($negative);
        unshift @bytes, 0 for(1..4-@bytes);
    }
    unless(@bytes) {
        @bytes = (0);
    }

    if($obj->{'snmp'}) {
        unshift @bytes, 0 if(!$negative and $bytes[0] > 0x79);
    }

    return wantarray ? @bytes : \@bytes;
}

=head2 ushort(\%h)

Takes a hash-ref, and byte-encodes C<$h-E<gt>{'value'}>. The value has to be an
unsigned short int.

=cut

sub ushort {
    my $obj      = shift;
    my $short    = $obj->{'value'};
    my $negative = $short < 0;
    my @bytes;

    if($obj->{'snmp'}) {
        unshift @bytes, 0 if(!$negative and $short > 0x79);
    }

    while($short) {
        my $value  = $short & 0xff;
        $short   >>= 8;
        $value    ^= 0xff if($negative);
        unshift @bytes, $value;
    }

    unless($obj->{'snmp'}) {
        $bytes[0] |= 0x80 if($negative);
        unshift @bytes, 0 for(1..2-@bytes);
    }

    @bytes = (0) unless(@bytes);

    return wantarray ? @bytes : \@bytes;
}

=head2 uchar(\%h)

Takes a hash-ref, and byte-encodes C<$h-E<gt>{'value'}>. The value has to be an
unsigned char.

=cut

sub uchar {
    my $value = 0xff & shift->{'value'};
    return wantarray ? ($value) : [$value];
}

=head2 vendorspec(\%h)

Takes a hash-ref, and byte-encodes it.

Example of the hash-ref:

 {
   value  => "0x001337", # vendors ID
   nested => {
     type   => "24", # vendor specific type
     value  => "42", # vendor specific value
   },
 }

=cut

sub vendorspec {
    my $obj    = shift;
    my $nested = $obj->{'nested'};
    my(@vendor, @bytes);

    return unless(ref $nested eq 'ARRAY');

    @vendor = ether($obj);
    @bytes  = (8, int(@vendor), @vendor);

    TLV:
    for my $tlv (@$nested) {
        my @value = hexstr($tlv);
        push @bytes, $tlv->{'type'};
        push @bytes, int @value;
        push @bytes, @value;
    }

    return wantarray ? @bytes : \@bytes;
}

=head2 ip(\%h)

Takes a hash-ref, and byte-encodes C<$h-E<gt>{'value'}>. The value need to an IPv4
address.

=cut

sub ip {
    defined $_[0]->{'value'} or return;
    my @value = split /\./, $_[0]->{'value'};
    return wantarray ? @value : [@value];
}

=head2 ether(\%h)

Takes a hash-ref, and byte-encodes C<$h-E<gt>{'value'}>. The value need to be a
six or twelve byte ethernet address.

=cut

sub ether {
    my $obj    = shift or return;
    my $string = $obj->{'value'};

    return unless(defined $string);

    if($string =~ /^\d+$/) { # numeric
        return uint({ value => $string });
    }
    elsif($string =~ /^(?:0x)?([0-9a-f]+)$/i) { # hex
        return hexstr({ value => $1 });
    }
}

=head2 string(\%h)

Takes a hash-ref, and byte-encodes C<$h-E<gt>{'value'}>. The string could be
anything in theory, but is often human-readable or a hex-string (leading 0x)

=cut

sub string {
    my $obj    = shift;
    my $string = $obj->{'value'};

    if($string =~ /^0x[a-z0-9]+$/i) { # hex
        return hexstr({ value => $string });
    }
    else { # normal
        $string =~ s/%(\w\w)/{ chr hex $1 }/ge;
        my @ret =  map { ord $_ } split //, $string;
        return wantarray ? @ret : \@ret;
    }
}

=head2 hexstr(\%h)

Takes a hash-ref, and byte-encodes C<$h-E<gt>{'value'}>. The value can have
leading '0x'.

=cut

sub hexstr {
    my $value = shift->{'value'} || '';
    my @bytes;

    $value =~ s/^(?:0x)//;

    if($value =~ /^([0-9a-f]+)$/i) {
        while($value) {
            $value =~ s/(\w{1,2})$// and unshift @bytes, hex $1;
        }
    }

    return wantarray ? @bytes: \@bytes;
}

=head1 AUTHOR

=head1 BUGS

=head1 SUPPORT

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

See L<DOCSIS::ConfigFile>

=cut

1;
