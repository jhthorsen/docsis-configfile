package DOCSIS::ConfigFile::Encode;
use strict;
use warnings;
use bytes;
use Carp 'confess';
use Math::BigInt;
use Socket;

our %SNMP_TYPE = (
  INTEGER   => [0x02, \&int],
  STRING    => [0x04, \&string],
  NULLOBJ   => [0x05, sub { }],
  OBJECTID  => [0x06, \&objectid],
  IPADDRESS => [0x40, \&ip],
  COUNTER   => [0x41, \&uint],
  UNSIGNED  => [0x42, \&uint],
  TIMETICKS => [0x43, \&uint],
  OPAQUE    => [0x44, \&uint],
  COUNTER64 => [0x46, \&bigint],
);

sub bigint {
  my $value = _test_value(bigint => $_[0]);
  my $int64 = Math::BigInt->new($value);

  $int64->is_nan and confess "$value is not a number";

  my $negative = $int64 < 0;
  my @bytes = $negative ? (0x80) : ();

  while ($int64) {
    my $value = $int64 & 0xff;
    $int64 >>= 8;
    $value ^= 0xff if ($negative);
    unshift @bytes, $value;
  }

  return @bytes ? @bytes : (0);    # 0 is also a number ;-)
}

sub ether {
  my $string = _test_value(ether => $_[0]);

  if ($string =~ qr{^\+?[0-4294967295]$}) {    # numeric
    return uint({value => $string});
  }
  elsif ($string =~ /^(?:0x)?([0-9a-f]+)$/i) {    # hex
    return hexstr({value => $1});
  }

  confess "ether({ value => $string }) is invalid";
}

sub hexstr {
  my $string = _test_value(hexstr => $_[0], qr{(?:0x)?([a-f0-9]+)}i);
  my @bytes;

  $string =~ s/^(?:0x)//;
  unshift @bytes, hex $1 while $string =~ s/(\w{1,2})$//;
  confess "hexstr({ value => ... }) is left with ($string) after decoding" if $string;
  return @bytes;
}

sub ip { split /\./, _test_value(ip => $_[0], qr{^(?:\d{1,3}\.){3}\d{1,3}$}) }

sub int {
  my $obj      = $_[0];
  my $int      = _test_value(int => $obj, qr{^[+-]?\d{1,10}$});
  my $negative = $int < 0;
  my @bytes;

  # make sure we're working on 32bit
  $int &= 0xffffffff;

  while ($int) {
    my $value = $int & 0xff;
    $int >>= 8;
    $value ^= 0xff if ($negative);
    unshift @bytes, $value;
  }

  if (!$obj->{snmp}) {
    $bytes[0] |= 0x80 if ($negative);
    unshift @bytes, 0 for (1 .. 4 - @bytes);
  }
  if (@bytes == 0) {
    @bytes = (0);
  }
  if ($obj->{snmp}) {
    unshift @bytes, 0 if (!$negative and $bytes[0] > 0x79);
  }

  return @bytes;
}

sub mic      { }
sub no_value { }

sub objectid {
  my $oid = _test_value(objectid => $_[0], qr{^\.?\d+(\.\d+)+$});
  $oid =~ s/^\.//;
  return _snmp_oid($oid);
}

sub snmp_object {
  my $obj = _test_value(snmp_object => $_[0]);
  my $type = $SNMP_TYPE{uc($obj->{type})} or confess "Unknown SNMP type: @{[$obj->{type}||'']}";
  my @value = $type->[1]->({value => $obj->{value}, snmp => 1});
  my @oid = _snmp_oid($obj->{oid});

  unless (@value) {
    confess 'Failed to decode SNMP value: ' . $obj->{value};
  }

  my @oid_length   = _snmp_length(0 + @oid);
  my @value_length = _snmp_length(0 + @value);
  my @total_length = _snmp_length(3 + @value + @oid + @value_length);

  return (
    #-type--------length----------value-----type---
    0x30, @total_length,        # object
    0x06, @oid_length, @oid,    # oid
    $type->[0], @value_length, @value,    # value
  );
}

sub string {
  my $string = _test_value(string => $_[0]);
  return hexstr(@_) if $string =~ /^0x[a-f0-9]+$/i;
  $string =~ s/%(\w\w)/{ chr hex $1 }/ge;
  return map { ord $_ } split //, $string;
}

sub stringz {
  my @bytes = string(@_);
  push @bytes, 0 if (@bytes == 0 or $bytes[-1] ne "\0");
  return @bytes;
}

sub uchar { _test_value(uchar => $_[0], qr/\+?\d{1,3}$/) }

sub uint {
  my $obj = $_[0];
  my $uint = _test_value(uint => $obj, qr{^\+?\d{1,10}$});
  my @bytes;

  while ($uint) {
    my $value = $uint & 0xff;
    $uint >>= 8;
    unshift @bytes, $value;
  }

  if (!$obj->{snmp}) {
    unshift @bytes, 0 for (1 .. 4 - @bytes);
  }
  if (@bytes == 0) {
    @bytes = (0);
  }
  if ($obj->{snmp}) {
    unshift @bytes, 0 if ($bytes[0] > 0x79);
  }

  return @bytes;
}

sub ushort {
  my $obj = $_[0];
  my $ushort = _test_value(ushort => $obj, qr{^\+?\d{1,5}$});
  my @bytes;

  unshift @bytes, 0 if $obj->{snmp} and $ushort > 0x79;

  while ($ushort) {
    my $value = $ushort & 0xff;
    $ushort >>= 8;
    unshift @bytes, $value;
  }

  map { unshift @bytes, 0 } 1 .. 2 - @bytes unless $obj->{snmp};
  return @bytes ? @bytes : (0);
}

sub vendor {
  my $options = $_[0]->{value}{options};
  my @vendor  = ether({value => $_[0]->{value}{id}});
  my @bytes   = (8, CORE::int(@vendor), @vendor);

  for (my $i = 0; $i < @$options; $i += 2) {
    my @value = hexstr({value => $options->[$i + 1]});
    push @bytes, uchar({value => $options->[$i]});
    push @bytes, CORE::int(@value);
    push @bytes, @value;
  }

  return @bytes;
}

sub vendorspec {
  my $obj = $_[0];
  my (@vendor, @bytes);

  confess "vendor({ nested => ... }) is not an array ref" unless ref $obj->{nested} eq 'ARRAY';

  @vendor = ether($obj);                       # will extract value=>$hexstr. might confess
  @bytes = (8, CORE::int(@vendor), @vendor);

  for my $tlv (@{$obj->{nested}}) {
    my @value = hexstr($tlv);                  # will extract value=>$hexstr. might confess
    push @bytes, uchar({value => $tlv->{type}});
    push @bytes, CORE::int(@value);
    push @bytes, @value;
  }

  return @bytes;
}

sub _snmp_length {
  my $length = $_[0];
  my @bytes;

  return $length if $length < 0x80;
  return 0x81, $length if $length < 0xff;
  confess "Too long snmp length: ($length)" unless $length < 0xffff;

  while ($length) {
    unshift @bytes, $length & 0xff;
    $length >>= 8;
  }

  return 0x82, @bytes;
}

sub _snmp_oid {
  my $oid = $_[0];
  my (@encoded_oid, @input_oid);
  my $subid = 0;

  if ($_[0] =~ /[A-Za-z]/) {
    die "[DOCSIS] Need to install SNMP.pm http://www.net-snmp.org/ to encode non-numberic OID $oid"
      unless DOCSIS::ConfigFile::CAN_TRANSLATE_OID;
    $oid = SNMP::translateObj($oid) or confess "Could not translate OID '$_[0]'";
  }

  @input_oid = split /\./, $oid;
  shift @input_oid unless length $input_oid[0];

  # the first two sub-id are in the first id
  {
    my $first  = shift @input_oid;
    my $second = shift @input_oid;
    push @encoded_oid, $first * 40 + $second;
  }

SUB_OID:
  for my $id (@input_oid) {
    if ($id <= 0x7f) {
      push @encoded_oid, $id;
    }
    else {
      my @suboid;

      while ($id) {
        unshift @suboid, 0x80 | ($id & 0x7f);
        $id >>= 7;
      }

      $suboid[-1] &= 0x7f;
      push @encoded_oid, @suboid;
    }
  }

  return @encoded_oid;
}

sub _test_value {
  my ($name, $obj, $test) = @_;

  confess "$name({ value => ... }) received undefined value" unless defined $obj->{value};
  confess "$name({ value => " . $obj->{value} . " }) does not match $test" if $test and not $obj->{value} =~ $test;
  $obj->{value};
}

1;

=encoding utf8

=head1 NAME

DOCSIS::ConfigFile::Encode - Encode functions for a DOCSIS config-file.

=head1 DESCRIPTION

L<DOCSIS::ConfigFile::Encode> has functions which is used to encode "human"
data into list of unsigned characters (0-255) (refered to as "bytes") later in
the pod. This list can then be encoded into binary data using:

  $bytestr = pack 'C*', @uchar;

=head1 FUNCTIONS

=head2 bigint

Returns a list of bytes representing the C<$bigint>. This can be any
number (negative or positive) which can be representing using 64 bits.

=head2 ether

This function use either L</uint> or L</hexstr> to encode the
input value. It will figure out the function to use by checking
the input for either integer value or a string looking like
a hex-string.

=head2 hexstr

Will encode any hex encoded string into a list of bytes. The string
can have an optional leading "0x".

=head2 int

Returns a list of bytes representing the C<$int>. This can be any
number (negative or positive) which can be representing using 32 bits.

=head2 ip

Returns a list of four bytes representing the C<$ip>. The C<$ip> must
be in in the format "1.2.3.4".

=head2 objectid

Encodes MIB number as value of C<OBJECTID>
can be in format: 1.2.3.4, .1.2.3.4

=head2 mic

Cannot encode CM/CMTS mic without complete information about
the config file, so this function returns an empty list.

=head2 no_value

This method will return an empty list. It is used by DOCSIS types, which
has zero length.

=head2 snmp_object

This function encodes a human-readable SNMP oid into a list of bytes:

  @bytes = (
    #-type---length---------value-----type---
    0x30,  $total_length,         # object
    0x06,  int(@oid),     @oid,   # oid
    $type, int(@value),   @value, # value
  );

=head2 string

Returns a list of bytes representing the C<$str>. Will use
L</hexstr> to decode it if it looks like a hex string (a
string starting with leading "0x"). In other cases, it will
decode it itself. The input string might also be encoded
with a simple uri-encode format: "%20" will be translated
to a space, and "%25" will be translated into "%", before
encoded using C<ord()>.

=head2 stringz

Returns a list of bytes representing the C<$str> with a zero
terminator at the end. The "\0" byte will be added unless
seen as the last element in the list.

Only ServiceClassName needs this, see C<$DOCSIS::ConfigFile::TREE> for more
details.

=head2 uchar

Returns a list with one byte representing the C<$uchar>. This can be any
positive number which can be representing using 8 bits.

=head2 uint

Returns a list of bytes representing the C<$uint>. This can be any
positive number which can be representing using 32 bits.

=head2 ushort

Returns a list of bytes representing the C<$ushort>. This can be any
positive number which can be representing using 16 bits.

=head2 vendor

Will byte-encode a complex vendorspec datastructure.

=head2 vendorspec

Will byte-encode a complex vendorspec datastructure.

=head1 SEE ALSO

L<DOCSIS::ConfigFile>

=cut
