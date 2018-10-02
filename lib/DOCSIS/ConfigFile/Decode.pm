package DOCSIS::ConfigFile::Decode;
use strict;
use warnings;
use bytes;

use Carp 'confess';
use DOCSIS::ConfigFile::Syminfo;
use Math::BigInt;
use Socket;

our %SNMP_TYPE = (
  0x02 => ['INTEGER',   \&int],
  0x04 => ['STRING',    \&string],
  0x05 => ['NULLOBJ',   sub { }],
  0x40 => ['IPADDRESS', \&ip],
  0x41 => ['COUNTER',   \&uint],
  0x42 => ['UNSIGNED',  \&uint],
  0x43 => ['TIMETICKS', \&uint],
  0x44 => ['OPAQUE',    \&uint],
  0x46 => ['COUNTER64', \&bigint],
);

sub bigint {
  my @bytes    = unpack 'C*', _test_length(int => $_[0]);
  my $negative = $bytes[0] & 0x80;
  my $int64    = Math::BigInt->new(0);

  # setup int64
  for my $chunk (@bytes) {
    $chunk ^= 0xff if ($negative);
    $int64 = ($int64 << 8) | $chunk;
  }

  if ($negative) {
    $int64 *= -1;
    $int64 -= 1;
  }

  return $int64;
}

sub ether {
  my $length = length $_[0];
  return join '', unpack 'H2' x $length, $_[0] if $length == 6 or $length == 12;
  confess "Invalid ether input. Invalid length ($length)";
}

sub hexstr { '0x' . join '', unpack 'H*', $_[0] }

sub int {
  my @bytes    = unpack 'C*', _test_length(int => $_[0], 'int');
  my $negative = $bytes[0] & 0x80;
  my $int      = 0;

  for my $chunk (@bytes) {
    $chunk ^= 0xff if ($negative);
    $int = ($int << 8) | $chunk;
  }

  if ($negative) {
    $int *= -1;
    $int -= 1;
  }

  return $int;
}

sub ip { inet_ntoa($_[0]) || confess 'inet_ntoa(...) failed to unpack binary string' }
sub mic      {&hexstr}
sub no_value {''}

sub snmp_object {
  my $bin = $_[0];
  my ($byte, $length, $oid, $type, $value);

  # message
  $type = _truncate_and_unpack(\$bin, 'C1');    # 0x30
  $length = _snmp_length(\$bin);

  # oid
  $type   = _truncate_and_unpack(\$bin, 'C1');    # 0x06
  $length = _snmp_length(\$bin);
  $oid    = _snmp_oid(\$bin, $length);

  # value
  $type   = $SNMP_TYPE{_truncate_and_unpack(\$bin, 'C1')};
  $length = _snmp_length(\$bin);
  $value  = $type->[1]->($bin);

  return {oid => $oid, type => $type->[0], value => $value};
}

sub string {

  # not sure why this is able to join - may be removed later
  my $bin = @_ > 1 ? join '', map { chr $_ } @_ : $_[0];

  return hexstr($bin) if $bin =~ /^[^\t\n\r\x20-\xEF]/;
  $bin =~ s/([^\x20-\x24\x26-\x7e])/{ sprintf "%%%02x", ord $1 }/ge;
  return $bin;
}

sub stringz { my $str = string(@_); $str =~ s/%00$//; $str; }
sub uchar { unpack 'C', _test_length(uchar => $_[0], 'char') }

sub uint {
  my @bytes = unpack 'C*', _test_length(uint => $_[0], 'int');
  my $value = 0;

  $value = ($value << 8) | $_ for (@bytes);
  return $value;
}

sub ushort { unpack 'n', _test_length(ushort => $_[0], 'short int') }

sub vendorspec {
  my $bin = $_[0] || '';
  my ($vendor, @ret, $length);

  # extract length (not sure what the first byte is...)
  $bin =~ s/^.(.)//s or confess 'Invalid vendorspec input. Could not extract length';
  $length = unpack 'C', $1;

  # extract vendor
  $bin =~ s/^(.{$length})//s or confess 'Invalid vendorspec input. Could not extract vendor';
  $vendor = sprintf '0x' . ('%02x' x $length), unpack 'C*', $1;

  # extract TLV
  while ($bin =~ s/^(.)(.)//s) {
    my $type   = unpack 'C*', $1;
    my $length = unpack 'C*', $2;

    if ($bin =~ s/^(.{$length})//s) {
      push @ret, {type => $type, length => $length, value => hexstr($1)};
    }
  }

  confess "vendorspec('...') is left with ($length) bytes after decoding" if $length = length $bin;
  return $vendor, \@ret;
}

sub vendor {
  my $bin = shift || '';
  my $length = $bin =~ s/^.(.)//s ? unpack 'C', $1 : 0;
  my ($id, @options);

  if ($bin =~ s/^(.{$length})//s) {
    $id = sprintf "0x@{['%02x' x $length]}", unpack 'C*', $1;
  }

  while ($bin =~ s/^(.)(.)//s) {
    my $type   = unpack 'C*', $1;
    my $length = unpack 'C*', $2;

    $bin =~ s/^(.{$length})//s or next;
    push @options, $type, hexstr($1);
  }

  confess 'Bytes left in vendorspec' if length $bin;
  confess 'Invalid vendorspec' unless defined $id;
  return {id => $id, options => \@options};
}

sub _byte_size {
  return 2  if lc $_[0] eq 'short int';
  return 4  if lc $_[0] eq 'int';
  return 4  if lc $_[0] eq 'long int';
  return 1  if lc $_[0] eq 'char';
  return 4  if lc $_[0] eq 'float';
  return 8  if lc $_[0] eq 'double';
  return 12 if lc $_[0] eq 'long double';
  return 16 if lc $_[0] eq 'md5digest';
}

sub _snmp_length {
  my $length = _truncate_and_unpack($_[0], 'C1');    # length?

  if ($length <= 0x80) {
    return $length;
  }
  elsif ($length == 0x81) {
    return _truncate_and_unpack($_[0], 'C1');
  }
  elsif ($length == 0x82) {
    $length = 0;

    for my $byte (_truncate_and_unpack($_[0], 'C2')) {
      $length = $length << 8 | $byte;
    }

    return $length;
  }

  confess "Too long SNMP length: ($length)";
}

sub _snmp_oid {
  my @bytes = _truncate_and_unpack($_[0], 'C' . $_[1]);
  my @oid   = (0);
  my $subid = 0;

  for my $id (@bytes) {
    if ($subid & 0xfe000000) {
      confess "_snmp_oid(@bytes): Sub-identifier too large: ($subid)";
    }

    $subid = ($subid << 7) | ($id & 0x7f);

    unless ($id & 0x80) {
      confess "_snmp_oid(@bytes): Exceeded max length" if (128 <= @oid);
      push @oid, $subid;
      $subid = 0;
    }
  }

  # the first two sub-id are in the first id
  if ($oid[1] == 0x2b) {    # Handle the most common case
    $oid[0] = 1;
    $oid[1] = 3;
  }
  elsif ($oid[1] < 40) {
    $oid[0] = 0;
  }
  elsif ($oid[1] < 80) {
    $oid[0] = 1;
    $oid[1] -= 40;
  }
  else {
    $oid[0] = 2;
    $oid[1] -= 80;
  }

  return SNMP::translateObj(join '.', @oid) || join '.', @oid if DOCSIS::ConfigFile::Syminfo::CAN_TRANSLATE_OID;
  return join '.', @oid;
}

sub _test_length {
  my $name   = $_[0];
  my $length = length $_[1];

  if (!$length) {
    confess "$name(...) bytestring length is zero";
  }
  if ($_[2]) {
    my $max = _byte_size($_[2]);
    confess "$name(...) bytestring length is invalid: $max < $length" if ($max < $length);
  }

  return $_[1];
}

sub _truncate_and_unpack {
  my ($bin_ref, $type) = @_;
  my $n = ($type =~ /C/ ? 1 : 2) * ($type =~ /(\d+)/)[0];

  if ($$bin_ref =~ s/^(.{$n})//s) {
    return unpack $type, $1;
  }
  else {
    confess "_truncate_and_unpack('...', $type) failed to truncate binary string";
  }
}

1;

=encoding utf8

=head1 NAME

DOCSIS::ConfigFile::Decode - Decode functions for a DOCSIS config-file

=head1 DESCRIPTION

L<DOCSIS::ConfigFile::Decode> has functions which is used to decode binary data
into either plain strings or complex data structures, dependent on the function
called.

=head1 FUNCTIONS

=head2 bigint

Returns a C<Math::BigInt> object.

=head2 ether

Will unpack the input string and return a MAC address in this format:
"00112233" or "00112233445566".

=head2 hexstr

Will unpack the input string and a string with leading "0x", followed
by hexidesimal characters.

=head2 int

Will unpack the input string and return an integer, from -2147483648
to 2147483647.

=head2 ip

Will unpack the input string and return a human readable IPv4 address.

=head2 string

Returns human-readable string, where special characters are "uri encoded".
Example: "%" = "%25" and " " = "%20". It can also return the value from
L</hexstr> if it starts with a weird character, such as C<\x00>.

=head2 stringz

Same as string above. However this string is zero-terminated in encoded
form, but this function remove the last "\0" seen in the string.

=head2 mic

Returns a value, printed as hex.

=head2 no_value

This method will return an empty string. It is used by DOCSIS types, which
has zero length.

=head2 snmp_object

Will take a binary string and decode it into a complex
datastructure, with "oid", "type" and "value".

=head2 uchar

Will unpack the input string and return a short integer, from 0 to 255.

=head2 uint

Will unpack the input string and return an integer, from 0 to 4294967295.

=head2 ushort

Will unpack the input string and return a short integer, from 0 to 65535.

=head2 vendor

Will byte-encode a complex vendorspec datastructure.

=head2 vendorspec

Will unpack the input string and return a complex datastructure,
representing the vendor specific data.

=head1 SEE ALSO

L<DOCSIS::ConfigFile>

=cut
