package DOCSIS::ConfigFile;

=head1 NAME

DOCSIS::ConfigFile - Decodes and encodes DOCSIS config files

=head1 VERSION

0.64

=head1 DESCRIPTION

L<DOCSIS::ConfigFile> is a class which provides functionality to decode and
encode L<DOCSIS|http://www.cablelabs.com> (Data over Cable Service Interface
Specifications) config files.

This module is used as a layer between any human readable data and
the binary structure.

The files are usually served using a L<TFTP server|Mojo::TFTPd>, after a
L<cable modem|http://en.wikipedia.org/wiki/Cable_modem> or MTA (Multimedia
Terminal Adapter) has recevied an IP address from a L<DHCP|Net::ISC::DHCPd>
server. These files are L<binary encode|DOCSIS::ConfigFile::Encode> using a
variety of functions, but all the data in the file are constructed by TLVs
(type-length-value) blocks. These can be nested and concatenated.

=head1 SYNOPSIS

  use DOCSIS::ConfigFile qw( encode_docsis decode_docsis );

  $data = decode_docsis $bytes;

  $bytes = encode_docsis(
             {
               GlobalPrivacyEnable => 1,
               MaxCPE              => 2,
               NetworkAccess       => 1,
               BaselinePrivacy => {
                 AuthTimeout       => 10,
                 ReAuthTimeout     => 10,
                 AuthGraceTime     => 600,
                 OperTimeout       => 1,
                 ReKeyTimeout      => 1,
                 TEKGraceTime      => 600,
                 AuthRejectTimeout => 60,
                 SAMapWaitTimeout  => 1,
                 SAMapMaxRetries   => 4
               },
               SnmpMibObject => [
                 {oid => '1.3.6.1.4.1.1.77.1.6.1.1.6.2',    INTEGER => 1},
                 {oid => '1.3.6.1.4.1.1429.77.1.6.1.1.6.2', STRING  => 'bootfile.bin'}
               ],
               VendorSpecific => {
                 id => '0x0011ee',
                 options => [30 => '0xff', 31 => '0x00', 32 => '0x28']
               }
             }
           );

=head1 OPTIONAL MODULE

You can install the L<SNMP.pm|SNMP> module to translate between SNMP
OID formats. With the module installed, you can define the C<SnmpMibObject>
like the example below, instead of using numeric OIDs:

  encode_docsis(
    {
      SnmpMibObject => [
        {oid => 'docsDevNmAccessIp.1',             IPADDRESS => '10.0.0.1'},
        {oid => 'docsDevNmAccessIpMask.1',         IPADDRESS => '255.255.255.255'},
      ]
    },
  );

=cut

use strict;
use warnings;
use Digest::MD5;
use Digest::HMAC_MD5;
use Digest::SHA;
use DOCSIS::ConfigFile::Syminfo;
use DOCSIS::ConfigFile::Decode;
use DOCSIS::ConfigFile::Encode;
use constant DEBUG => $ENV{DOCSIS_CONFIGFILE_DEBUG} || 0;

use base 'Exporter';

our $VERSION   = '0.64';
our @EXPORT_OK = qw( decode_docsis encode_docsis );
our $DEPTH     = 0;

=head1 FUNCTIONS

=head2 decode_docsis

  $data = decode_docsis($byte_string);

Used to decode a DOCSIS config file into a data structure. The output
C<$data> can be used as input to L</encode_docsis>. Note: C<$data>
will only contain array-refs if the DOCSIS parameter occur more than
once.

=cut

sub decode_docsis {
  my $args = ref $_[-1] eq 'HASH' ? $_[-1] : {};
  my $current = $args->{blueprint} || $DOCSIS::ConfigFile::Syminfo::TREE;
  my $end     = $args->{end}       || length $_[0];
  my $pos     = $args->{pos}       || 0;
  my $data    = {};

  local $DEPTH = $DEPTH + 1 if DEBUG;

  while ($pos < $end) {
    my $code = unpack 'C', substr $_[0], $pos++, 1 or next;    # next on $code=0
    my ($length, $t, $name, $syminfo, $value);

    for (keys %$current) {
      next unless $code == $current->{$_}{code};
      $name    = $_;
      $syminfo = $current->{$_};
      last;
    }

    if (!$name) {
      warn "[DOCSIS] Internal error: No syminfo defined for code=$code.";
      next;
    }

    # Document: PKT-SP-PROV1.5-I03-070412
    # Chapter:  9.1 MTA Configuration File
    $t = $syminfo->{lsize} == 1 ? 'C' : 'n';    # 1=C, 2=n
    $length = unpack $t, substr $_[0], $pos, $syminfo->{lsize};
    $pos += $syminfo->{lsize};

    if ($syminfo->{nested}) {
      warn "[DOCSIS]@{[' 'x$DEPTH]}Decode $name [$pos, $length] with encode_docsis\n" if DEBUG;
      local @$args{qw( blueprint end pos)} = ($syminfo->{nested}, $length + $pos, $pos);
      $value = decode_docsis($_[0], $args);
    }
    elsif (my $f = DOCSIS::ConfigFile::Decode->can($syminfo->{func})) {
      warn "[DOCSIS]@{[' 'x$DEPTH]}Decode $name [$pos, $length] with $syminfo->{func}\n" if DEBUG;
      $value = $f->(substr $_[0], $pos, $length);
      $value = {oid => @$value{qw( oid type value )}} if $name eq 'SnmpMibObject';
    }
    else {
      die qq(Can't locate object method "$syminfo->{func}" via package "DOCSIS::ConfigFile::Decode");
    }

    $pos += $length;

    if (!exists $data->{$name}) {
      $data->{$name} = $value;
    }
    elsif (ref $data->{$name} eq 'ARRAY') {
      push @{$data->{$name}}, $value;
    }
    else {
      $data->{$name} = [$data->{$name}, $value];
    }
  }

  return $data;
}

=head2 encode_docsis

  $byte_string = encode_docsis(\%data, \%args);

Used to encode a data structure into a DOCSIS config file. Each of the keys
in C<$data> can either hold a hash- or array-ref. An array-ref is used if
the same DOCSIS parameter occur multiple times. These two formats will result
in the same C<$byte_string>:

  # Only one SnmpMibObject
  encode_docsis({
    SnmpMibObject => { # hash-ref
      oid => '1.3.6.1.4.1.1429.77.1.6.1.1.6.2', STRING => 'bootfile.bin'
    }
  })

  # Allow one or more SnmpMibObjects
  encode_docsis({
    SnmpMibObject => [ # array-ref of hashes
      { oid => '1.3.6.1.4.1.1429.77.1.6.1.1.6.2', STRING => 'bootfile.bin' }
    ]
  })

Possible C<%args>:

=over 4

=item * mta_algorithm

This argument is required when encoding MTA config files.

=item * shared_secret

This argument is optional, but will be used as the shared secret used to
increase security between the cable modem and CMTS.

=back

=cut

sub encode_docsis {
  my ($data, $args) = @_;
  my $current = $args->{blueprint} || $DOCSIS::ConfigFile::Syminfo::TREE;
  my $mic     = {};
  my $bytes   = '';

  local $args->{depth} = ($args->{depth} || 0) + 1;
  local $DEPTH = $args->{depth} if DEBUG;

  for my $name (sort { $current->{$a}{code} <=> $current->{$b}{code} } keys %$current) {
    next unless defined $data->{$name};
    my $syminfo = $current->{$name};
    my ($type, $length, $value);

    for my $item (ref $data->{$name} eq 'ARRAY' ? @{$data->{$name}} : $data->{$name}) {
      if ($syminfo->{nested}) {
        warn "[DOCSIS]@{[' 'x$DEPTH]}Encode $name with encode_docsis\n" if DEBUG;
        local @$args{qw( blueprint )} = ($current->{$name}{nested});
        $value = encode_docsis($item, $args);
      }
      elsif (my $f = DOCSIS::ConfigFile::Encode->can($syminfo->{func})) {
        warn "[DOCSIS]@{[' 'x$DEPTH]}Encode $name with $syminfo->{func}\n" if DEBUG;
        if ($name eq 'SnmpMibObject') {
          my @k = qw( type value );
          local $item->{oid} = $item->{oid};
          $value = pack 'C*', $f->({value => {oid => delete $item->{oid}, map { shift(@k), $_ } %$item}});
        }
        else {
          local $syminfo->{name} = $name;
          $value = pack 'C*', $f->({value => _validate($item, $syminfo)});
        }
      }
      else {
        die qq(Can't locate object method "$syminfo->{func}" via package "DOCSIS::ConfigFile::Encode");
      }

      $type = pack 'C', $syminfo->{code};
      $length = $syminfo->{lsize} == 2 ? pack('n', length $value) : pack('C', length $value);
      $mic->{$name} = "$type$length$value";
      $bytes .= $mic->{$name};
    }
  }

  return $bytes if $args->{depth} != 1;
  return $bytes . _cm_eof($bytes, $mic, $args);
}

sub _cm_eof {
  my $mic      = $_[1];
  my $args     = $_[2];
  my $cmts_mic = '';
  my $pads     = 4 - (1 + length $_[0]) % 4;
  my $eod_pad;

  $mic->{CmMic} = pack('C*', 6, 16) . Digest::MD5::md5($_[0]);

  $cmts_mic .= $mic->{$_} || '' for @DOCSIS::ConfigFile::Syminfo::CMTS_MIC;
  $cmts_mic = pack('C*', 7, 16) . Digest::HMAC_MD5::hmac_md5($cmts_mic, $args->{shared_secret} || '');
  $eod_pad = pack('C', 255) . ("\0" x $pads);

  return $mic->{CmMic} . $cmts_mic . $eod_pad;
}

# _validate($value, $syminfo);
sub _validate {
  if ($_[1]->{limit}[1]) {
    if ($_[0] =~ /^-?\d+$/) {
      die "[DOCSIS] $_[1]->{name} holds a too high value. ($_[0])" if $_[1]->{limit}[1] < $_[0];
      die "[DOCSIS] $_[1]->{name} holds a too low value. ($_[0])"  if $_[0] < $_[1]->{limit}[0];
    }
    else {
      my $length = length $_[0];
      die "[DOCSIS] $_[1]->{name} is too long. ($_[0])"  if $_[1]->{limit}[1] < $length;
      die "[DOCSIS] $_[1]->{name} is too short. ($_[0])" if $length < $_[1]->{limit}[0];
    }
  }
  return $_[0];
}

=head1 ATTRIBUTES

=head2 advanced_output

Deprecated.

=head2 shared_secret

Deprecated. Use L</encode_docsis> instead.

=head1 METHODS

=head2 new

Deprecated. Use L</decode_docsis> or L</encode_docsis> instead.

=head2 decode

Deprecated. Use L</decode_docsis> instead.

=head2 encode

Deprecated. Use L</encode_docsis> instead.

=cut

use Carp 'confess';
use constant Syminfo => "DOCSIS::ConfigFile::Syminfo";
use constant Decode  => "DOCSIS::ConfigFile::Decode";
use constant Encode  => "DOCSIS::ConfigFile::Encode";

sub shared_secret {
  my $self = shift;
  $self->{shared_secret} = $_[0] if (@_);
  return $self->{shared_secret} ||= q();
}

sub advanced_output {
  my $self = shift;
  $self->{advanced_output} = $_[0] if (@_);
  return $self->{advanced_output} || 0;
}

sub new {
  my $class = shift;
  my $args  = ref $_[0] eq 'HASH' ? $_[0] : {@_};
  my $self  = bless $args, $class;
  return $self;
}

sub decode {
  no warnings 'newline';    # don't shout on invalid filename

  my $self = shift;
  my $input = shift || '__undefined_input__';
  my $FH;

  if (ref $input eq 'SCALAR') {    # binary string
    open $FH, '<', $input;
  }
  elsif (ref $input eq 'GLOB') {    # input is filehandle
    $FH = $input;
  }
  elsif (-f $input) {               # input is filename
    open $FH, '<', $input;
  }
  else {
    confess 'Usage: $self->decode( ScalarRef|GlobRef|Filename )';
  }

  binmode $FH;
  $self->{decode_fh} = $FH;

  return $self->_decode_loop;
}

sub _decode_loop {
  my $self    = shift;
  my $tlength = shift || 0xffffffff;
  my $p_code  = shift || 0;
  my $FH      = $self->{decode_fh};
  my $cfg     = [];

CODE:
  while ($tlength > 0) {
    my $code = $self->_read_code($FH) or last CODE;
    my $syminfo = Syminfo->from_code($code, $p_code);
    my $length = $self->_read_length($FH, $syminfo->length);
    my ($value, $nested);

    $tlength -= $length + 2;

    if (!defined $syminfo->func) {
      next CODE;
    }
    elsif ($syminfo->func eq 'nested') {
      $nested = $self->_decode_loop($length, $syminfo->code);
    }
    elsif (my $decoder = Decode->can($syminfo->func)) {
      ($value, $nested) = $decoder->($self->_read_value($FH, $length));
    }
    else {
      $self->_read_value($FH, $length);
      die sprintf 'Unknown decode method for PCODE/CODE (%s/%s). (%s) bytes are thrown away', $p_code, $code, $length;
      next CODE;
    }

    if (defined $value or defined $nested) {
      push @$cfg, $self->_value_to_cfg($syminfo, $length, $value, $nested);
      next CODE;
    }

    die sprintf 'Could not decode PCODE/CODE (%s/%s) using function (%s)', $p_code, $code, $syminfo->func;
  }

  return $cfg;
}

sub _read_code {
  my ($self, $FH) = @_;
  my $bytes = read $FH, my ($data), 1;

  return $bytes ? unpack 'C', $data : '';
}

sub _read_length {
  my $self = shift;
  my $read = read $_[0], my ($length), $_[1];

  # Document: PKT-SP-PROV1.5-I03-070412
  # Chapter:  9.1 MTA Configuration File
  return
      $read == 0 ? 0
    : $read == 1 ? unpack('C', $length)
    : $read == 2 ? unpack('n', $length)
    : 0xffffffff    # weird way to enforce error later on...
    ;
}

sub _read_value {
  my ($self, $FH, $length) = @_;
  my $bytes = read $FH, my ($data), $length;

  if ($bytes != $length) {
    confess sprintf 'Expected to read (%s) bytes. Read (%s) bytes', $length, $bytes;
  }

  return $data;
}

sub _value_to_cfg {
  my $self    = shift;
  my $syminfo = shift;
  my $length  = shift;
  my $value   = shift;
  my $nested  = shift;

  if ($self->advanced_output) {
    return {
      name   => $syminfo->id,
      code   => $syminfo->code,
      pcode  => $syminfo->pcode,
      func   => $syminfo->func,
      llimit => $syminfo->l_limit,
      ulimit => $syminfo->u_limit,
      length => $length,
      (defined $value ? (value => $value) : ()), (defined $nested ? (nested => $nested) : ()),
    };
  }
  else {
    return {
      name => $syminfo->id,
      (defined $value ? (value => $value) : ()), (defined $nested ? (nested => $nested) : ()),
    };
  }
}

sub encode {
  my $self   = shift;
  my $config = shift || '__undefined_input__';
  my $algo   = shift;

  if (ref $config ne 'ARRAY') {
    confess 'Usage: $self->encode( ArrayRef[HashRef] )';
  }

  if ($algo and $algo !~ /^(?:md5|sha1)$/i) {
    confess "Usage: $self->encode( ArrayRef[HashRef], 'md5|sha1' )";
  }
  $algo = lc $algo if $algo;

  $self->{cmts_mic} = {};
  $self->{binstring} = $self->_encode_loop($config) || q();

  if (grep { $_->{name} eq 'MtaConfigDelimiter' } @$config) {
    $self->{_MtaConfigDelimiter} = 1;    # for internal usage

    if ($self->{binstring} and $algo) {
      my $hash = $algo eq 'md5' ? md5_hex $self->{binstring} : Digest::SHA::sha1_hex($self->{binstring});

      if ($hash) {
        splice @$config, $#{$config}, 0,
          {
          name  => 'SnmpMibObject',
          value => {oid => '1.3.6.1.4.1.4491.2.2.1.1.2.7.0', type => 'STRING', value => "0x${hash}"}
          };

        $self->{binstring} = $self->_encode_loop($config) || q();
      }
    }
  }
  else {
    $self->{_DefaultConfigDelimiter} = 1;    # for internal usage

    my $cm_mic   = $self->_calculate_cm_mic;
    my $cmts_mic = $self->_calculate_cmts_mic;
    my $eod_pad  = $self->_calculate_eod_and_pad;

    $self->{binstring} .= "$cm_mic$cmts_mic$eod_pad";
  }

  return $self->{binstring};
}

sub _encode_loop {
  my $self      = shift;
  my $config    = shift || '__undefined_input__';
  my $level     = shift || 0;
  my $i         = shift || 0;
  my $binstring = q();

  if (ref $config ne 'ARRAY') {
    confess sprintf 'Input is not an array ref: %s', $config;
  }

TLV:
  for my $tlv (@$config) {
    confess sprintf 'Invalid TLV#%s: %s', $i, $tlv || '__undefined_tlv__' unless (ref $tlv eq 'HASH');
    confess sprintf 'Missing name in TLV#%s: %s', $i, join(',', keys %$tlv) unless ($tlv->{name});

    my $name    = $tlv->{name};
    my $syminfo = Syminfo->from_id($name);
    my ($type, $length, $value);

    if (!defined $syminfo->func) {
      next TLV;
    }
    elsif ($syminfo->func eq 'nested') {
      $value = $self->_encode_loop($tlv->{nested}, $level + 1, $i);
    }
    elsif (my $encoder = Encode->can($syminfo->func)) {
      $value = pack 'C*', $encoder->($tlv) or next TLV;
    }
    else {
      die sprintf 'Unknown encode method for TLV#%s/%s', $i, $name;
      next TLV;
    }

    $syminfo = $self->_syminfo_from_syminfo_siblings($syminfo, $tlv);
    $type    = $syminfo->code;
    $length  = $syminfo->length == 2 ? pack 'n', length $value : pack 'C', length $value;

    $type = pack "C", $type;
    $binstring .= "$type$length$value";

    $self->_calculate_cmts_mic($name, "$type$length$value");
  }
  continue {
    $i++;
  }

  return $binstring;
}

sub _syminfo_from_syminfo_siblings {
  my ($self, $syminfo, $tlv) = @_;
  my @error;

SIBLING:
  for my $sibling (@{$syminfo->siblings}) {
    unless ($sibling->l_limit or $sibling->u_limit) {
      next SIBLING;
    }

    my $value = $tlv->{value} =~ /^\d+$/ ? $tlv->{value} : length $tlv->{value};

    if ($value > $sibling->u_limit) {
      push @error, sprintf '%s/%s: %s > %s', $sibling->pcode, $sibling->code, $value, $sibling->u_limit;
    }
    elsif ($value < $sibling->l_limit) {
      push @error, sprintf '%s/%s: %s < %s', $sibling->pcode, $sibling->code, $value, $sibling->l_limit;
    }
    else {
      return $sibling;
    }
  }

  confess sprintf 'Invalid value for %s: %s', $syminfo->id, join ', ', @error if @error;
  return $syminfo;
}

sub _calculate_eod_and_pad {
  my $self   = shift;
  my $length = length $self->{binstring};
  my $pads   = 4 - (1 + $length) % 4;

  return pack("C", 255) . ("\0" x $pads);
}

sub _calculate_cm_mic {
  my $self = shift;
  my $cm_mic = pack("C*", 6, 16) . Digest::MD5::md5($self->{binstring});

  $self->_calculate_cmts_mic("CmMic", $cm_mic);

  return $cm_mic;
}

sub _calculate_cmts_mic {
  my $self     = shift;
  my $cmts_mic = $self->{cmts_mic};
  my $data;

  if (@_ == 2) {
    my $name = shift;
    my $val  = shift;
    return $cmts_mic->{$name} .= $val;
  }
  else {
    for my $code (Syminfo->cmts_mic_codes) {
      $data .= $cmts_mic->{$code} || '';
    }

    return (join "", pack("C*", 7, 16), Digest::HMAC_MD5::hmac_md5($data, $self->shared_secret));
  }
}

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014, Jan Henning Thorsen

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 AUTHOR

Jan Henning Thorsen - C<jhthorsen@cpan.org>

=cut

1;
