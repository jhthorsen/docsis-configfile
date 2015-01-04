package DOCSIS::ConfigFile::Syminfo;

=head1 NAME

DOCSIS::ConfigFile::Syminfo - Symbolinfo for a DOCSIS config-file

=head1 VERSION

See DOCSIS::ConfigFile

=head1 SYNOPSIS

    use DOCSIS::ConfigFile::Syminfo;

    my @objs = DOCSIS::ConfigFile::Syminfo->from_id($ID);
    my $obj = DOCSIS::ConfigFile::Syminfo->from_code($CODE, $PCODE);

=head1 DESCRIPTION

This module holds many pre-defined DOCSIS 1.x and 2.0 TLVs. The
definitions are used to translate between binary and something that
is human readable. It also holds information to validate the data,
to make sure not "garbage" is written to the config file. The names
and information found in this module is "stolen" from the
L<docsis project|http://docsis.sourceforge.net/> source code.

NOTE: DOCSIS 3.0 is also supported, since the main differences is in
the physical layer and not the config file.

=cut

use strict;
use warnings;
use autodie;
use Carp qw( cluck confess );

my %FROM_CODE;
my %FROM_ID;
my @OBJECT_ATTRIBUTES = qw( id code pcode func l_limit u_limit length );

=head1 CLASS METHODS

=head2 add_symbol

    $class->add_symbol({
        id => $str,      # MaxRateDown
        code => $int,    # 2
        pcode => $int,   # 4
        func => $str,    # uint
        l_limit => $int, # 0
        u_limit => $int, # 52000000
        length => $int,  # 1
    });

This method can be used to globally add new DOCSIS symbols, unless not yet
supported. See the source code for more examples. Please file a
L<bug|https://github.com/jhthorsen/docsis-configfile/issues>
with the new symbol, so others can use it as well.

=cut

sub add_symbol {
  my $class  = shift;
  my $symbol = shift;
  my $key;

  # meant for internal usage...
  if (ref $symbol eq 'ARRAY') {
    $symbol = {map { $_ => shift @$symbol } @OBJECT_ATTRIBUTES};
  }

  if (my @missing = grep { !exists $symbol->{$_} } @OBJECT_ATTRIBUTES) {
    confess(
      sprintf 'add_symbol({ id=>%s, pcode=>%s, code=>%s, ... }) missing attributes: %s',
      (map { $symbol->{$_} || '' } qw/ id pcode code /),
      (join ',', @missing),
    );
  }

  $key = join '-', $symbol->{pcode}, $symbol->{code};

  if ($FROM_CODE{$key}) {
    confess(
      sprintf 'Key collision (%s): (%s) tries to overwrite (%s)',
      $key,
      (join ',', map { $symbol->{$_} } @OBJECT_ATTRIBUTES),
      (join ',', map { $FROM_CODE{$key}->{$_} } @OBJECT_ATTRIBUTES),
    );
  }

  $FROM_CODE{$key} = $symbol;
  push @{$FROM_ID{$symbol->{id}}}, $symbol;

  return 1;
}

=head2 dump_symbol_tree

    $str = $self->dump_symbol_tree;

This method will return a dump of the symbol tree, similar to
L<Data::Dumper>.

Curious of the config tree which is supported by default? Run the
command below, to see the syminfo tree:

    perl -e'print +(require DOCSIS::ConfigFile::Syminfo)->dump_symbol_tree'

=cut

sub TO_JSON {
  my ($class, $tree, $pcode, $seen) = @_;

  $pcode ||= 0;
  $tree  ||= {};
  $seen  ||= {};

  for my $symbol (sort { $a->{id} cmp $b->{id} } values %FROM_CODE) {
    next if $symbol->{code} == 0;
    next if $symbol->{pcode} != $pcode;
    next if $seen->{$symbol}++;

    my $current = $tree->{$symbol->{id}} = {%$symbol};

    if ($symbol->{func} =~ qr{nested|vendorspec}) {
      $current->{$symbol->{func}} = $class->TO_JSON({}, $symbol->{code}, $seen);
    }

    $current->{limit} = [@$symbol{qw( l_limit u_limit )}];
    delete $current->{$_} for qw( pcode id l_limit u_limit );
  }

  return $tree;
}

sub dump_symbol_tree {
  my $class   = shift;
  my $pcode   = shift || 0;
  my $_seen   = shift || {};
  my $_indent = shift || 0;
  my @str;

  for my $symbol (sort { $a->{id} cmp $b->{id} } values %FROM_CODE) {
    next if ($_seen->{$symbol});
    next if ($symbol->{pcode} != $pcode);
    next if ($symbol->{code} == 0);
    my $width = 40 - $_indent * 2;

    $_seen->{$symbol} = 1;

    #               UpstreamChannelId   2   0  uchar    0  255    1
    push @str,
      sprintf(
      "%s%-${width}s %3s %3s  %-11s %10s %10s\n",
      ('  ' x $_indent),
      (map { defined $symbol->{$_} ? $symbol->{$_} : '' } @OBJECT_ATTRIBUTES),
      );

    if ($symbol->{func} =~ qr{nested|vendorspec}) {
      push @str, $class->dump_symbol_tree($symbol->{code}, $_seen, $_indent + 1);
    }
  }

  return @str if wantarray;
  return join '', map { (' ' x $pcode) . "$_\n" } @str;
}

=head2 from_id

    $self = $class->from_id($ID);
    $self = $class->from_id('BaselinePrivacy');

Returns one L<DOCSIS::ConfigFile::Syminfo> objects, which might point
to siblings.

=cut

sub from_id {
  my $class = shift;
  my $id    = shift;
  my @objs;

  return $class->_undef_symbol unless ($id);
  return $class->_undef_symbol unless ($FROM_ID{$id});

  @objs = map { bless \%{$_}, $class } @{$FROM_ID{$id}};

  $objs[0]->{siblings} = \@objs;

  return $objs[0];
}

=head2 from_code

    $self = $class->from_code($CODE, $PCODE);

Returns one L<DOCSIS::ConfigFile::Syminfo> object.

=cut

sub from_code {
  my $class = shift;
  my $code  = shift || 0;
  my $pcode = shift || 0;

  return $class->_undef_symbol unless (defined $code and defined $pcode);
  return $class->_undef_symbol unless ($FROM_CODE{"$pcode-$code"});
  return bless $FROM_CODE{"$pcode-$code"}, $class;
}

sub _undef_symbol {
  my $class = shift;

  return bless {id => '', code => -1, pcode => -1, func => '', length => 0,}, $class;
}

=head2 undef_row

This method will be deprecated.

=cut

{
  no warnings;
  *undef_row = sub {
    cluck 'Will be deprecated. Use _undef_symbol() instead';
    &_undef_symbol;
  };
}

=head2 cmts_mic_codes

    @str = $class->cmts_mic_codes;

Returns a list of all the codes that defines the CMTS MIC.

=cut

sub cmts_mic_codes {
  qw/
    DownstreamFrequency  UpstreamChannelId
    NetworkAccess        ClassOfService
    BaselinePrivacy      VendorSpecific
    CmMic                MaxCPE
    TftpTimestamp        TftpModemAddress
    UsPacketClass        DsPacketClass
    UsServiceFlow        DsServiceFlow
    MaxClassifiers       GlobalPrivacyEnable
    PHS                  SubMgmtControl
    SubMgmtCpeTable      SubMgmtFilters
    TestMode
    /;
}

=head2 byte_size

    $int = $class->byte_size($type);
    $int = $class->byte_size('short int');

Returns the number of bytes a type takes.

=cut

sub byte_size {
  return 2  if (lc $_[1] eq 'short int');
  return 4  if (lc $_[1] eq 'int');
  return 4  if (lc $_[1] eq 'long int');
  return 1  if (lc $_[1] eq 'char');
  return 4  if (lc $_[1] eq 'float');
  return 8  if (lc $_[1] eq 'double');
  return 12 if (lc $_[1] eq 'long double');
  return 16 if (lc $_[1] eq 'md5digest');
}

=head1 OBJECT METHODS

=head2 id

Returns the identifier.
Returns "" on error.

=head2 code

Returns the DOCSIS code.
Returns -1 on error.

=head2 pcode

Returns the DOCSIS parent code.
Returns -1 on error.

=head2 func

Returns the name of the function to be used when decoding/encoding.
Returns "" on error.

=head2 l_limit

Returns the lower limit numeric value.
Returns -1 on error.

=head2 u_limit

Returns the upper limit numeric value.
Returns -1 on error.

=head2 length

Tells how many bytes long the length is.

=head2 siblings

Used with L<from_id()>: Gives multiple objects, with the same ID.

=cut

sub id       { $_[0]->{id} }
sub code     { $_[0]->{code} }
sub pcode    { $_[0]->{pcode} }
sub func     { $_[0]->{func} }
sub l_limit  { $_[0]->{l_limit} }
sub u_limit  { $_[0]->{u_limit} }
sub length   { $_[0]->{length} }
sub siblings { $_[0]->{siblings} }

#==================================================================================
#     ID                     CODE PCODE   FUNC         L_LIMIT   H_LIMIT     LENGTH
#     identifier      docsis_code   pID   func         low_limit high_limit  length
#----------------------------------------------------------------------------------
__PACKAGE__->add_symbol($_)
  for (
  [qw( Pad                       0     0   nested       0         255         1 )],
  [qw( DownstreamFrequency       1     0   uint         88000000  860000000   1 )],
  [qw( UpstreamChannelId         2     0   uchar        0         255         1 )],
  [qw( CmMic                     6     0   mic          0         0           1 )],
  [qw( CmtsMic                   7     0   mic          0         0           1 )],
  [qw( NetworkAccess             3     0   uchar        0         1           1 )],
  [qw( ClassOfService            4     0   nested       0         0           1 )],
  [qw( ClassID                   1     4   uchar        1         16          1 )],
  [qw( MaxRateDown               2     4   uint         0         52000000    1 )],
  [qw( MaxRateUp                 3     4   uint         0         10000000    1 )],
  [qw( PriorityUp                4     4   uchar        0         7           1 )],
  [qw( GuaranteedUp              5     4   uint         0         10000000    1 )],
  [qw( MaxBurstUp                6     4   ushort       0         65535       1 )],
  [qw( PrivacyEnable             7     4   uchar        0         1           1 )],
  [qw( SwUpgradeFilename         9     0   string       0         0           1 )],
  [qw( SnmpWriteControl         10     0   nested       0         0           1 )],
  [qw( SnmpMibObject            11     0   snmp_object  1         255         1 )],
  [qw( CpeMacAddress            14     0   ether        0         0           1 )],
  [qw( BaselinePrivacy          17     0   nested       0         0           1 )],
  [qw( AuthTimeout               1    17   uint         1         30          1 )],
  [qw( ReAuthTimeout             2    17   uint         1         30          1 )],
  [qw( AuthGraceTime             3    17   uint         1         6047999     1 )],
  [qw( OperTimeout               4    17   uint         1         10          1 )],
  [qw( ReKeyTimeout              5    17   uint         1         10          1 )],
  [qw( TEKGraceTime              6    17   uint         1         302399      1 )],
  [qw( AuthRejectTimeout         7    17   uint         1         600         1 )],
  [qw( MaxCPE                   18     0   uchar        1         254         1 )],
  [qw( SwUpgradeServer          21     0   ip           0         0           1 )],

  # DOCSIS1 .1-2.0
  [qw( UsPacketClass            22     0   nested       0         0           1 )],
  [qw( ClassifierRef             1    22   uchar        1         255         1 )],
  [qw( ClassifierId              2    22   ushort       1         65535       1 )],
  [qw( ServiceFlowRef            3    22   ushort       1         65535       1 )],
  [qw( ServiceFlowId             4    22   uint         1         4294967295  1 )],
  [qw( RulePriority              5    22   uchar        0         255         1 )],
  [qw( ActivationState           6    22   uchar        0         1           1 )],
  [qw( DscAction                 7    22   uchar        0         2           1 )],
  [qw( IpPacketClassifier        9    22   nested       0         0           1 )],
  [qw( IpTos                     1     9   hexstr       3         3           1 )],
  [qw( IpProto                   2     9   ushort       0         257         1 )],
  [qw( IpSrcAddr                 3     9   ip           0         0           1 )],
  [qw( IpSrcMask                 4     9   ip           0         0           1 )],
  [qw( IpDstAddr                 5     9   ip           0         0           1 )],
  [qw( IpDstMask                 6     9   ip           0         0           1 )],
  [qw( SrcPortStart              7     9   ushort       0         65535       1 )],
  [qw( SrcPortEnd                8     9   ushort       0         65535       1 )],
  [qw( DstPortStart              9     9   ushort       0         65535       1 )],
  [qw( DstPortEnd               10     9   ushort       0         65535       1 )],
  [qw( LLCPacketClassifier      10    22   nested       0         0           1 )],
  [qw( DstMacAddress             1    10   ether        0         0           1 )],
  [qw( SrcMacAddress             2    10   ether        0         0           1 )],
  [qw( EtherType                 3    10   hexstr       0         0           1 )],
  [qw( IEEE802Classifier        11    22   nested       0         0           1 )],
  [qw( UserPriority              1    11   ushort       0         0           1 )],
  [qw( VlanID                    2    11   ushort       0         0           1 )],

  # TODO: Vendor Specific support in the IEEE802Classifier
  [qw( DsPacketClass            23     0   nested       0         0           1 )],
  [qw( ClassifierRef             1    23   uchar        1         255         1 )],
  [qw( ClassifierId              2    23   ushort       1         65535       1 )],
  [qw( ServiceFlowRef            3    23   ushort       1         65535       1 )],
  [qw( ServiceFlowId             4    23   uint         1         4294967295  1 )],
  [qw( RulePriority              5    23   uchar        0         255         1 )],
  [qw( ActivationState           6    23   uchar        0         1           1 )],
  [qw( DscAction                 7    23   uchar        0         2           1 )],
  [qw( IpPacketClassifier        9    23   nested       0         0           1 )],

  #[qw( IpTos                     1     9   hexstr       3         3           1 )], # already defined
  #[qw( IpProto                   2     9   ushort       0         257         1 )], # already defined
  #[qw( IpSrcAddr                 3     9   ip           0         0           1 )], # already defined
  #[qw( IpSrcMask                 4     9   ip           0         0           1 )], # already defined
  #[qw( IpDstAddr                 5     9   ip           0         0           1 )], # already defined
  #[qw( IpDstMask                 6     9   ip           0         0           1 )], # already defined
  #[qw( SrcPortStart              7     9   ushort       0         65535       1 )], # already defined
  #[qw( SrcPortEnd                8     9   ushort       0         65535       1 )], # already defined
  #[qw( DstPortStart              9     9   ushort       0         65535       1 )], # already defined
  #[qw( DstPortEnd               10     9   ushort       0         65535       1 )], # already defined
  [qw( LLCPacketClassifier      10    23   nested       0         0           1 )],

  #[qw( DstMacAddress             1    10   ether        0         0           1 )], # already defined
  #[qw( SrcMacAddress             2    10   ether        0         0           1 )], # already defined
  #[qw( EtherType                 3    10   hexstr       0         255         1 )], # already defined
  [qw( IEEE802Classifier        11    23   nested       0         0           1 )],

  #[qw( UserPriority              1    11   ushort       0         0           1 )], # already defined
  #[qw( VlanID                    2    11   ushort       0         0           1 )], # already defined

  # Upstream Service Flow
  [qw( UsServiceFlow            24     0   nested       0         0           1 )],
  [qw( UsServiceFlowRef          1    24   ushort       1         65535       1 )],
  [qw( UsServiceFlowId           2    24   uint         1         4294967295  1 )],
  [qw( ServiceClassName          4    24   stringz      2         16          1 )],
  [qw( QosParamSetType           6    24   uchar        0         255         1 )],
  [qw( TrafficPriority           7    24   uchar        0         7           1 )],
  [qw( MaxRateSustained          8    24   uint         0         0           1 )],
  [qw( MaxTrafficBurst           9    24   uint         0         0           1 )],
  [qw( MinReservedRate          10    24   uint         0         0           1 )],
  [qw( MinResPacketSize         11    24   ushort       0         65535       1 )],
  [qw( ActQosParamsTimeout      12    24   ushort       0         65535       1 )],
  [qw( AdmQosParamsTimeout      13    24   ushort       0         65535       1 )],
  [qw( UsVendorSpecific         43    24   vendorspec   0         0           1 )],

  # Upstream Service Flow Specific params
  [qw( MaxConcatenatedBurst     14    24   ushort       0         65535       1 )],
  [qw( SchedulingType           15    24   uchar        0         6           1 )],
  [qw( RequestOrTxPolicy        16    24   hexstr       0         255         1 )],
  [qw( NominalPollInterval      17    24   uint         0         0           1 )],
  [qw( ToleratedPollJitter      18    24   uint         0         0           1 )],
  [qw( UnsolicitedGrantSize     19    24   ushort       0         65535       1 )],
  [qw( NominalGrantInterval     20    24   uint         0         0           1 )],
  [qw( ToleratedGrantJitter     21    24   uint         0         0           1 )],
  [qw( GrantsPerInterval        22    24   uchar        0         127         1 )],
  [qw( IpTosOverwrite           23    24   hexstr       0         255         1 )],

  # Downstream Service Flow
  [qw( DsServiceFlow            25     0   nested       0         0           1 )],
  [qw( DsServiceFlowRef          1    25   ushort       1         65535       1 )],
  [qw( DsServiceFlowId           2    25   uint         1         4294967295  1 )],
  [qw( ServiceClassName          4    25   stringz      2         16          1 )],
  [qw( QosParamSetType           6    25   uchar        0         255         1 )],
  [qw( TrafficPriority           7    25   uchar        0         7           1 )],
  [qw( MaxRateSustained          8    25   uint         0         4294967295  1 )],
  [qw( MaxTrafficBurst           9    25   uint         0         4294967295  1 )],
  [qw( MinReservedRate          10    25   uint         0         4294967295  1 )],
  [qw( MinResPacketSize         11    25   ushort       0         65535       1 )],
  [qw( ActQosParamsTimeout      12    25   ushort       0         65535       1 )],
  [qw( AdmQosParamsTimeout      13    25   ushort       0         65535       1 )],
  [qw( DsVendorSpecific         43    25   vendorspec   0         0           1 )],

  # Downstream Service Flow Specific Params
  [qw( MaxDsLatency             14    25   uint         0         0           1 )],

  # Payload Header Suppression - Appendix C.2.2.8
  [qw( PHS                      26     0   nested       0         0           1 )],
  [qw( PHSClassifierRef          1    26   uchar        1         255         1 )],
  [qw( PHSClassifierId           2    26   ushort       1         65535       1 )],
  [qw( PHSServiceFlowRef         3    26   ushort       1         65535       1 )],
  [qw( PHSServiceFlowId          4    26   uint         1         4294967295  1 )],

  # Payload Header Suppression Rule - Appendix C.2.2.10
  [qw( PHSField                  7    26   hexstr       1         255         1 )],
  [qw( PHSIndex                  8    26   uchar        1         255         1 )],
  [qw( PHSMask                   9    26   hexstr       1         255         1 )],
  [qw( PHSSize                  10    26   uchar        1         255         1 )],
  [qw( PHSVerify                11    26   uchar        0         1           1 )],
  [qw( MaxClassifiers           28     0   ushort       0         0           1 )],
  [qw( GlobalPrivacyEnable      29     0   uchar        0         0           1 )],

  # BPI+ SubTLV  s
  [qw( SAMapWaitTimeout          8    17   uint         1         10          1 )],
  [qw( SAMapMaxRetries           9    17   uint         0         10          1 )],

  # ManufacturerCVC
  [qw( MfgCVCData               32     0   hexstr       0         0           1 )],

  # Vendor Specific
  [qw( VendorSpecific           43     0   vendorspec   0         0           1 )],
  [qw( VendorIdentifier          8    43   hexstr       3         3           1 )],

  # SNMPv3 Kickstart
  [qw( SnmpV3Kickstart          34     0   nested       0         0           1 )],

  # TODO: SP-RFI-v2.0 says the SecurityName is UTF8 encoded
  [qw( SnmpV3SecurityName        1    34   string       1         16          1 )],
  [qw( SnmpV3MgrPublicNumber     2    34   hexstr       1         514         1 )],

  # Snmpv3 Notification Receiver
  [qw( SnmpV3TrapReceiver       38     0   nested       0         0           1 )],
  [qw( SnmpV3TrapRxIP            1    38   ip           0         0           1 )],
  [qw( SnmpV3TrapRxPort          2    38   ushort       0         0           1 )],
  [qw( SnmpV3TrapRxType          3    38   ushort       1         5           1 )],
  [qw( SnmpV3TrapRxTimeout       4    38   ushort       0         65535       1 )],
  [qw( SnmpV3TrapRxRetries       5    38   ushort       0         65535       1 )],
  [qw( SnmpV3TrapRxFilterOID     6    38   ushort       1         5           1 )],
  [qw( SnmpV3TrapRxSecurityName  7    38   string       1         16          1 )],
  [qw( DocsisTwoEnable          39     0   uchar        0         1           1 )],

  # Modem Capabilities Encodings
  [qw( ModemCapabilities         5     0   nested       0         0           1 )],
  [qw( ConcatenationSupport      1     5   uchar        0         1           1 )],
  [qw( ModemDocsisVersion        2     5   uchar        0         2           1 )],
  [qw( FragmentationSupport      3     5   uchar        0         1           1 )],
  [qw( PHSSupport                4     5   uchar        0         1           1 )],
  [qw( IGMPSupport               5     5   uchar        0         1           1 )],
  [qw( BaselinePrivacySupport    6     5   uchar        0         1           1 )],
  [qw( DownstreamSAIDSupport     7     5   uchar        0         255         1 )],
  [qw( UpstreamSIDSupport        8     5   uchar        0         255         1 )],
  [qw( DCCSupport               12     5   uchar        0         1           1 )],
  [qw( SubMgmtControl           35     0   hexstr       3         3           1 )],
  [qw( SubMgmtCpeTable          36     0   hexstr       0         0           1 )],
  [qw( SubMgmtFilters           37     0   ushort_list  4         4           1 )],
  [qw( SnmpCpeAccessControl     55     0   uint         0         1           1 )],
  [qw( SnmpMibObject            64     0   snmp_object  1         65535       2 )],
  [qw( TestMode                 40     0   hexstr       0         1           1 )],

  # PacketCable MTA Configuration File Delimiter
  [qw( MtaConfigDelimiter      254     0   uchar        1         255         1 )],
  [qw( DsChannelList            41     0   nested       1         255         1 )],
  [qw( SingleDsChannel           1    41   nested       1         255         1 )],
  [qw( SingleDsTimeout           1     1   ushort       0         65535       1 )],
  [qw( SingleDsFrequency         2     1   uint         0         4294967295  1 )],
  [qw( DsFreqRange               2    41   nested       1         255         1 )],
  [qw( DsFreqRangeTimeout        1     2   ushort       0         65535       1 )],
  [qw( DsFreqRangeStart          2     2   uint         0         4294967295  1 )],
  [qw( DsFreqRangeEnd            3     2   uint         0         4294967295  1 )],
  [qw( DsFreqRangeStepSize       4     2   uint         0         4294967295  1 )],
  [qw( DefaultScanTimeout        3    41   ushort       0         65535       1 )],
  [qw( TftpTimestamp            19     0   uint         0         4294967295  1 )],
  [qw( TftpModemAddress         20     0   ip           0         0           1 )],

  # Generic TLV... we only use the limits  code and length dont matter
  [qw( GenericTLV              255     0   no_value     0         0           1 )],
  );

#-------------------------------------------------------------------------------------
#        ID                     CODE PCODE   FUNC         L_LIMIT   H_LIMIT     LENGTH
#=====================================================================================

=head1 AUTHOR

Jan Henning Thorsen - C<jhthorsen@cpan.org>

=cut

__PACKAGE__;
