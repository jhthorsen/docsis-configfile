package DOCSIS::ConfigFile;

=head1 NAME

DOCSIS::ConfigFile - Decodes and encodes DOCSIS config-files

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

  $bytes = encode_docsis \%data, \%args;
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
                 SAMapMaxRetries   => 4,
               },
               VendorSpecific => {
                 "0x02" => {
                   "foo" => "123",
                 }
               },
             },
             {
               shared_secret => "s3cret",
               algorithm     => "sha1", # or "md5"
             }
           );

=cut

use strict;
use warnings;
use autodie;
use Carp qw( carp confess );
use Digest::MD5;
use Digest::HMAC_MD5;
use Digest::SHA 'sha1_hex';
use DOCSIS::ConfigFile::Syminfo;
use DOCSIS::ConfigFile::Decode;
use DOCSIS::ConfigFile::Encode;
use constant DEBUG => $ENV{DOCSIS_CONFIGFILE_DEBUG} || 0;

use base 'Exporter';

our @EXPORT_OK = qw( decode_docsis encode_docsis );
our $DEPTH     = 0;

use constant Syminfo => "DOCSIS::ConfigFile::Syminfo";
use constant Decode  => "DOCSIS::ConfigFile::Decode";
use constant Encode  => "DOCSIS::ConfigFile::Encode";

our $VERSION = '0.64';

=head1 FUNCTIONS

These functions can be imported. See L</SYNOPSIS>.

=head2 decode_docsis

  $data = decode_docsis($bytes);

Used to decode a DOCSIS config file into a data structure.

=cut

sub decode_docsis {
  my $args = ref $_[-1] eq 'HASH' ? $_[-1] : {};
  my $current = $args->{blueprint} || $DOCSIS::ConfigFile::Syminfo::TREE;
  my $end     = $args->{end}       || length $_[0];
  my $pos     = $args->{pos}       || 0;
  my $data    = {};

  local $DEPTH = $DEPTH + 1 if DEBUG;

  while ($pos < $end) {
    my $code = unpack 'C', substr $_[0], $pos++, 1;
    my ($length, $t, $name, $value);

    for (keys %$current) {
      next unless $code == $current->{$_}{code};
      $name = $_;
      last;
    }

    if (!$name) {
      warn "[DOCSIS] Internal error: No syminfo defined for code=$code.";
      next;
    }

    # Document: PKT-SP-PROV1.5-I03-070412
    # Chapter:  9.1 MTA Configuration File
    $t = $current->{$name}{lsize} == 1 ? 'C' : 'n';    # 1=C, 2=n
    $length = unpack $t, substr $_[0], $pos, $current->{$name}{lsize};
    $pos += $current->{$name}{lsize};

    if ($current->{$name}{nested}) {
      warn "[DOCSIS]@{[' 'x$DEPTH]}Decode $name [$pos, $length] with encode_docsis\n" if DEBUG;
      local @$args{qw( blueprint end pos)} = ($current->{$name}{nested}, $length + $pos, $pos);
      $data->{$name} = decode_docsis($_[0], $args);
    }
    elsif (my $f = DOCSIS::ConfigFile::Decode->can($current->{$name}{func})) {
      warn "[DOCSIS]@{[' 'x$DEPTH]}Decode $name [$pos, $length] with $current->{$name}{func}\n" if DEBUG;
      $data->{$name} = $f->(substr $_[0], $pos, $length);
    }
    else {
      die "[DOCSIS] Internal error: DOCSIS::ConfigFile::Decode::$name() is not defined";
    }

    $pos += $length;
  }

  return $data;
}

=head2 encode_docsis

  $bytes = decode_docsis(\%data, \%args);

Used to encode a data structure into a DOCSIS config file.

=cut

sub encode_docsis {
  my ($data, $args) = @_;
  my $current = $args->{blueprint} || $DOCSIS::ConfigFile::Syminfo::TREE;
  my $bytes = '';

  local $DEPTH = $DEPTH + 1 if DEBUG;

  for my $name (sort { $current->{$a}{code} <=> $current->{$b}{code} } keys %$current) {
    next unless defined $data->{$name};
    my $syminfo = $current->{$name};
    my ($type, $length, $value);

    if ($syminfo->{nested}) {
      warn "[DOCSIS]@{[' 'x$DEPTH]}Encode $name with encode_docsis\n" if DEBUG;
      local @$args{qw( blueprint )} = ($current->{$name}{nested});
      $value = encode_docsis($data->{$name}, $args);
    }
    elsif (my $f = DOCSIS::ConfigFile::Encode->can($syminfo->{func})) {
      warn "[DOCSIS]@{[' 'x$DEPTH]}Encode $name with $syminfo->{func}\n" if DEBUG;
      $value = pack 'C*', $f->(ref $data->{$name} ? $data->{$name} : {value => $data->{$name}});
    }
    else {
      die "[DOCSIS] Internal error: DOCSIS::ConfigFile::Encode::$name() is not defined";
    }

    $type = pack 'C', $syminfo->{code};
    $length = $syminfo->{lsize} == 2 ? pack('n', length $value) : pack('C', length $value);
    $bytes .= "$type$length$value";
  }

  return $bytes;
}

=head1 ATTRIBUTES

=head2 shared_secret

Sets or gets the shared secret.

=cut

sub shared_secret {
  my $self = shift;
  $self->{shared_secret} = $_[0] if (@_);
  return $self->{shared_secret} ||= q();
}

=head2 advanced_output

Sets weither advanced output should be enabled. Takes 0 or 1 as argument.
Advanced output is off (0) by default.

=cut

sub advanced_output {
  my $self = shift;
  $self->{advanced_output} = $_[0] if (@_);
  return $self->{advanced_output} || 0;
}

=head1 METHODS

=head2 new

    $self = $class->new(\%args);

Arguments can be:

 shared_secret   => Shared secret in encoded cm config file
 advanced_output => Advanced decoded config format
 mibs            => will set $ENV{MIBS} to load custom mibs

=cut

sub new {
  my $class = shift;
  my $args  = ref $_[0] eq 'HASH' ? $_[0] : {@_};
  my $self  = bless $args, $class;
  return $self;
}

=head2 decode

    $array_ref = $self->decode($path_to_file);
    $array_ref = $self->decode(\$binary_string);
    $array_ref = $self->decode($FH);

This method decodes a binary config file stored in either a file on disk,
a binary string, or a filehandle. It returns an array-ref of hashes,
containing the config as a perl data structure.

=cut

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

      #carp sprintf 'PCODE/CODE (%s/%s) gets skipped: No function to decode', $p_code, $code;
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
      carp sprintf 'Unknown decode method for PCODE/CODE (%s/%s). (%s) bytes are thrown away', $p_code, $code, $length;
      next CODE;
    }

    if (defined $value or defined $nested) {
      push @$cfg, $self->_value_to_cfg($syminfo, $length, $value, $nested);
      next CODE;
    }

    carp sprintf 'Could not decode PCODE/CODE (%s/%s) using function (%s)', $p_code, $code, $syminfo->func;
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

=head2 encode

    $binary_str = $self->encode([ { ... }, ... ]);

Encodes an array of hashes, containing the DOCSIS config-file settings and
returns a binary encoded string. See L</DESCRIPTION> and the unit tests for
example input. For other structures, see the table generated by
L<DOCSIS::ConfigFile::Syminfo/dump_symbol_tree>.

When enconding MTA config files another arugment is accepted:

    $binary_str = $self->encode([ { ... }, ... ], 'md5|sha1');

As 'pktcMtaDevProvConfigHash' does not need to be included in the config at all
times this param is optional. Only two variants are accpted - MD5, or SHA1
The algorithm will then be used to define value for 'pktcMtaDevProvConfigHash'
and this line will be added just above 'MtaConfigDelimiter' closing tag resulting in

    MtaConfigDelimiter 1;
    ...
    SnmpMibObject enterprises.4491.2.2.1.1.2.7.0 HexString 0x1a2b3c4d5e6f... ;
    MtaConfigDelimiter 255;

=cut

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
      my $hash = $algo eq 'md5' ? md5_hex $self->{binstring} : sha1_hex $self->{binstring};

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

      #carp sprintf 'TLV#%s/%s is skipped: No function to encode', $i, $name;
      next TLV;
    }
    elsif ($syminfo->func eq 'nested') {
      $value = $self->_encode_loop($tlv->{nested}, $level + 1, $i);
    }
    elsif (my $encoder = Encode->can($syminfo->func)) {
      $value = pack 'C*', $encoder->($tlv) or next TLV;
    }
    else {
      carp sprintf 'Unknown encode method for TLV#%s/%s', $i, $name;
      next TLV;
    }

    $syminfo = $self->_syminfo_from_syminfo_siblings($syminfo, $tlv);
    $type    = $syminfo->code;
    $length  = $syminfo->length == 2 ? pack 'n', length $value : pack 'C', length $value;

    #carp 'name=%s type=%i, length=%i', $name, $type, length($value);

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

    return (join "", pack("C*", 7, 16), Digest::HMAC_MD5::hmac_md5($data, $self->shared_secret),);
  }
}

=head1 CONSTANTS

=head2 Decode

Returns L<DOCSIS::ConfigFile::Decode>.

=head2 Encode

Returns L<DOCSIS::ConfigFile::Encode>.

=head2 Syminfo

Returns L<DOCSIS::ConfigFile::Syminfo>.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014, Jan Henning Thorsen

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 AUTHOR

Jan Henning Thorsen - C<jhthorsen@cpan.org>

=cut

1;
