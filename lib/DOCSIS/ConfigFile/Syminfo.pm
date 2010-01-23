package DOCSIS::ConfigFile::Syminfo;

=head1 NAME

DOCSIS::ConfigFile::Syminfo - Symbolinfo for a DOCSIS config-file

=head1 VERSION

See DOCSIS::ConfigFile

=head1 SYNOPSIS

 use DOCSIS::ConfigFile::Syminfo;

 my @objs = DOCSIS::ConfigFile::Syminfo->from_id($ID);
 my $obj  = DOCSIS::ConfigFile::Syminfo->from_code($CODE, $PCODE);

See The C<@SYMBOL_TABLE> in this sourcefile for possible values.

=cut

use strict;
use warnings;

my %FROM_CODE;
my %FROM_ID;

=head1 CLASS METHODS

=head2 add_symbol

 $class->add_symbol(\%row);

=cut

sub add_symbol {
    my $class = shift;
    my $row   = shift;

    $FROM_CODE{ join("-", $row->{'code'}, $row->{'pcode'}) } = $row;
    push @{ $FROM_ID{ $row->{'id'} } }, $row; 

    return 1;
}

=head1 METHODS

=head2 from_id

 @objs = $self->from_id($ID);

Returns one C<DOCSIS::ConfigFile::Syminfo> objects, which might point
to siblings.

=cut

sub from_id {
    my $class = shift;
    my $id    = shift;
    my @objs;

    return $class->undef_row unless($id);
    return $class->undef_row unless($FROM_ID{$id});

    @objs = map { bless \%{$_}, $class } @{ $FROM_ID{$id} };

    $objs[0]->{'siblings'} = \@objs;

    return $objs[0];
}

=head2 from_code

 $obj = $self->from_code($CODE, $PCODE);

Returns one C<DOCSIS::ConfigFile::Syminfo> object.

=cut

sub from_code {
    my $class = shift;
    my $code  = shift;
    my $pcode = shift || 0;

    return $class->undef_row unless(defined $code and defined $pcode);
    return $class->undef_row unless($FROM_CODE{"$code,$pcode"});
    return bless $FROM_CODE{"$code,$pcode"}, $class;
}

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

BEGIN {
    no strict 'refs';
    my @sub2index = qw/id code pcode func l_limit u_limit length siblings/;

    for my $sub (@sub2index) {
        *$sub = sub { shift->{$sub} };
    }
}

=head2 undef_row

Returns a row template

=cut

sub undef_row {
    return bless {
        id     => "",
        code   => -1,
        pcode  => -1,
        func   => "",
        length => 0,
    };
}

=head1 FUNCTIONS

=head2 cmts_mic_codes

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

=head2 byte_size(type)

Returns the number of bytes a type takes.

=cut

sub byte_size {
    return 2  if(lc $_[1] eq 'short int');
    return 4  if(lc $_[1] eq 'int');
    return 4  if(lc $_[1] eq 'long int');
    return 1  if(lc $_[1] eq 'char');
    return 4  if(lc $_[1] eq 'float');
    return 8  if(lc $_[1] eq 'double');
    return 12 if(lc $_[1] eq 'long double');
    return 16 if(lc $_[1] eq 'md5digest');
}

=head1 AUTHOR

=head1 BUGS

=head1 SUPPORT

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

See L<DOCSIS::ConfigFile>

=cut

BEGIN {
    my $SYM_INFO = q[
#============================================================================
# ID                    CODE PCODE  FUNC         L_LIMIT   H_LIMIT     LENGTH
# identifier     docsis_code   pID  func         low_limit high_limit  length
#============================================================================
Pad                        0    0                0         0           1
DownstreamFrequency        1    0   uint         88000000  860000000   1
UpstreamChannelId          2    0   uchar        0         255         1
CmMic                      6    0   mic          0         0           1
CmtsMic                    7    0   mic          0         0           1
NetworkAccess              3    0   uchar        0         1           1
ClassOfService             4    0   nested       0         0           1
ClassID                    1    4   uchar        1         16          1
MaxRateDown                2    4   uint         0         52000000    1
MaxRateUp                  3    4   uint         0         10000000    1
PriorityUp                 4    4   uchar        0         7           1
GuaranteedUp               5    4   uint         0         10000000    1
MaxBurstUp                 6    4   ushort       0         65535       1
PrivacyEnable              7    4   uchar        0         1           1
SwUpgradeFilename          9    0   string       0         0           1
SnmpWriteControl          10    0   nested       0         0           1
SnmpMibObject             11    0   snmp_object  1         255         1
CpeMacAddress             14    0   ether        0         0           1
BaselinePrivacy           17    0   nested       0         0           1
AuthTimeout                1   17   uint         1         30          1
ReAuthTimeout              2   17   uint         1         30          1
AuthGraceTime              3   17   uint         1         6047999     1
OperTimeout                4   17   uint         1         10          1
ReKeyTimeout               5   17   uint         1         10          1
TEKGraceTime               6   17   uint         1         302399      1
AuthRejectTimeout          7   17   uint         1         600         1
MaxCPE                    18    0   uchar        1         254         1
SwUpgradeServer           21    0   ip           0         0           1

# DOCSIS 1.1-2.0

UsPacketClass             22    0   nested       0         0           1
ClassifierRef              1   22   uchar        1         255         1
ClassifierId               2   22   ushort       1         65535       1
ServiceFlowRef             3   22   ushort       1         65535       1
ServiceFlowId              4   22   uint         1         0xFFFFFFFF  1
RulePriority               5   22   uchar        0         255         1
ActivationState            6   22   uchar        0         1           1
DscAction                  7   22   uchar        0         2           1
IpPacketClassifier         9   22   nested       0         0           1
IpTos                      1    9   hexstr       3         3           1
IpProto                    2    9   ushort       0         257         1
IpSrcAddr                  3    9   ip           0         0           1
IpSrcMask                  4    9   ip           0         0           1
IpDstAddr                  5    9   ip           0         0           1
IpDstMask                  6    9   ip           0         0           1
SrcPortStart               7    9   ushort       0         65535       1
SrcPortEnd                 8    9   ushort       0         65535       1
DstPortStart               9    9   ushort       0         65535       1
DstPortEnd                10    9   ushort       0         65535       1
LLCPacketClassifier       10   22   nested       0         0           1
DstMacAddress              1   10   ether        0         0           1
SrcMacAddress              2   10   ether        0         0           1
EtherType                  3   10   hexstr       0         0           1
IEEE 802Classifier        11   22   nested       0         0           1
UserPriority               1   11   ushort       0         0           1
VlanID                     2   11   ushort       0         0           1

 # TODO: Vendor Specific support in the IEEE802Classifier

DsPacketClass             23    0   nested       0         0           1
ClassifierRef              1   23   uchar        1         255         1
ClassifierId               2   23   ushort       1         65535       1
ServiceFlowRef             3   23   ushort       1         65535       1
ServiceFlowId              4   23   uint         1         0xFFFFFFFF  1
RulePriority               5   23   uchar        0         255         1
ActivationState            6   23   uchar        0         1           1
DscAction                  7   23   uchar        0         2           1
IpPacketClassifier         9   23   nested       0         0           1
IpTos                      1    9   hexstr       3         3           1
IpProto                    2    9   ushort       0         257         1
IpSrcAddr                  3    9   ip           0         0           1
IpSrcMask                  4    9   ip           0         0           1
IpDstAddr                  5    9   ip           0         0           1
IpDstMask                  6    9   ip           0         0           1
SrcPortStart               7    9   ushort       0         65535       1
SrcPortEnd                 8    9   ushort       0         65535       1
DstPortStart               9    9   ushort       0         65535       1
DstPortEnd                10    9   ushort       0         65535       1
LLCPacketClassifier       10   23   nested       0         0           1
DstMacAddress              1   10   ether        0         0           1
SrcMacAddress              2   10   ether        0         0           1
EtherType                  3   10   hexstr       0         255         1
IEEE802Classifier         11   23   nested       0         0           1
UserPriority               1   11   ushort       0         0           1
VlanID                     2   11   ushort       0         0           1

# Upstream Service Flow

UsServiceFlow             24    0   nested       0         0           1
UsServiceFlowRef           1   24   ushort       1         65535       1
UsServiceFlowId            2   24   uint         1         0xFFFFFFFF  1
ServiceClassName           4   24   string       2         16          1
QosParamSetType            6   24   uchar        0         255         1
TrafficPriority            7   24   uchar        0         7           1
MaxRateSustained           8   24   uint         0         0           1
MaxTrafficBurst            9   24   uint         0         0           1
MinReservedRate           10   24   uint         0         0           1
MinResPacketSize          11   24   ushort       0         65535       1
ActQosParamsTimeout       12   24   ushort       0         65535       1
AdmQosParamsTimeout       13   24   ushort       0         65535       1

# Upstream Service Flow Specific params

MaxConcatenatedBurst      14   24   ushort       0         65535       1
SchedulingType            15   24   uchar        0         6           1
RequestOrTxPolicy         16   24   hexstr       0         255         1
NominalPollInterval       17   24   uint         0         0           1
ToleratedPollJitter       18   24   uint         0         0           1
UnsolicitedGrantSize      19   24   ushort       0         65535       1
NominalGrantInterval      20   24   uint         0         0           1
ToleratedGrantJitter      21   24   uint         0         0           1
GrantsPerInterval         22   24   uchar        0         127         1
IpTosOverwrite            23   24   hexstr       0         255         1

# Downstream Service Flow

DsServiceFlow             25    0   nested       0         0           1
DsServiceFlowRef           1   25   ushort       1         65535       1
DsServiceFlowId            2   25   uint         1         0xFFFFFFFF  1
ServiceClassName           4   25   string       2         16          1
QosParamSetType            6   25   uchar        0         255         1
TrafficPriority            7   25   uchar        0         7           1
MaxRateSustained           8   25   uint         0         0xFFFFFFFF  1
MaxTrafficBurst            9   25   uint         0         0xFFFFFFFF  1
MinReservedRate           10   25   uint         0         0xFFFFFFFF  1
MinResPacketSize          11   25   ushort       0         65535       1
ActQosParamsTimeout       12   25   ushort       0         65535       1
AdmQosParamsTimeout       13   25   ushort       0         65535       1

# Downstream Service Flow Specific Params

MaxDsLatency              14   25   uint         0         0           1

# Payload Header Suppression - Appendix C.2.2.8

PHS                       26    0   nested       0         0           1
PHSClassifierRef           1   26   uchar        1         255         1
PHSClassifierId            2   26   ushort       1         65535       1
PHSServiceFlowRef          3   26   ushort       1         65535       1
PHSServiceFlowId           4   26   uint         1         0xFFFFFFFF  1

# Payload Header Suppression Rule - Appendix C.2.2.10

PHSField                   7   26   hexstr       1         255         1
PHSIndex                   8   26   uchar        1         255         1
PHSMask                    9   26   hexstr       1         255         1
PHSSize                   10   26   uchar        1         255         1
PHSVerify                 11   26   uchar        0         1           1
MaxClassifiers            28    0   ushort       0         0           1
GlobalPrivacyEnable       29    0   uchar        0         0           1

# BPI+ SubTLV  s

SAMapWaitTimeout           8   17   uint         1         10          1
SAMapMaxRetries            9   17   uint         0         10          1

# ManufacturerCVC

MfgCVCData                32    0   hexstr       0         0           1

# Vendor Specific

VendorSpecific            43    0   vendorspec   0         0           1
VendorIdentifier           8   43   hexstr       3         3           1

# SNMPv3 Kickstart

SnmpV3Kickstart           34    0   nested       0         0           1

# TODO: SP-RFI-v2.0 says the SecurityName is UTF8 encoded

SnmpV3SecurityName         1   34   string       1         16          1
SnmpV3MgrPublicNumber      2   34   hexstr       1         514         1

# Snmpv3 Notification Receiver

SnmpV3TrapReceiver        38    0   nested       0         0           1
SnmpV3TrapRxIP             1   38   ip           0         0           1
SnmpV3TrapRxPort           2   38   ushort       0         0           1
SnmpV3TrapRxType           3   38   ushort       1         5           1
SnmpV3TrapRxTimeout        4   38   ushort       0         65535       1
SnmpV3TrapRxRetries        5   38   ushort       0         65535       1
SnmpV3TrapRxFilterOID      6   38   ushort       1         5           1
SnmpV3TrapRxSecurityName   7   38   string       1         16          1
DocsisTwoEnable           39    0   uchar        0         1           1

# Modem Capabilities Encodings

ModemCapabilities          5    0   nested       0         0           1
ConcatenationSupport       1    5   uchar        0         1           1
ModemDocsisVersion         2    5   uchar        0         2           1
FragmentationSupport       3    5   uchar        0         1           1
PHSSupport                 4    5   uchar        0         1           1
IGMPSupport                5    5   uchar        0         1           1
BaselinePrivacySupport     6    5   uchar        0         1           1
DownstreamSAIDSupport      7    5   uchar        0         255         1
UpstreamSIDSupport         8    5   uchar        0         255         1
DCCSupport                12    5   uchar        0         1           1
SubMgmtControl            35    0   hexstr       3         3           1
SubMgmtCpeTable           36    0   hexstr       0         0           1
SubMgmtFilters            37    0   ushort_list  4         4           1
SnmpMibObject             64    0   snmp_object  1         65535       2
TestMode                  40    0   hexstr       0         1           1

# PacketCable MTA Configuration File Delimiter

MtaConfigDelimiter       254    0   uchar        1         255         1
DsChannelList             41    0   nested       1         255         1
SingleDsChannel            1   41   nested       1         255         1
SingleDsTimeout            1    1   ushort       0         65535       1
SingleDsFrequency          2    1   uint         0         0xFFFFFFFF  1
DsFreqRange                2   41   nested       1         255         1
DsFreqRangeTimeout         1    2   ushort       0         65535       1
DsFreqRangeStart           2    2   uint         0         0xFFFFFFFF  1
DsFreqRangeEnd             3    2   uint         0         0xFFFFFFFF  1
DsFreqRangeStepSize        4    2   uint         0         0xFFFFFFFF  1
DefaultScanTimeout         3   41   ushort       0         65535       1
TftpTimestamp             19    0   uint         0         0xFFFFFFFF  1
TftpModemAddress          20    0   ip           0         0           1

# Generic TLV... we only use the limits  code and length dont matter

GenericTLV                 0    0   nested       1         255         1
GenericTLV               255    0                0         0           1
    ];

    #
    # Convert $SYM_INFO string (table above) to something useful
    #
    # Using *DATA seems to breack DBIx::Class, without any good reason
    # Didn't bother to trace the rabit, so instead the config is read from
    # a string now.
    #
    #  Error:  Couldn't load class (Quelea::App) because: Can't call method "isa" on an undefined value at /usr/share/perl5/DBIx/Class/Schema.pm line 244.
    #  at /usr/share/perl5/DBIx/Class/Schema.pm line 244
    #       DBIx::Class::Schema::load_namespaces('Quelea::Schema', 'default_resultset_class', 'ResultSet') called at /path/to/Quelea-Schema/lib/Quelea/Schema.pm line 38
    #       require Quelea/Schema.pm called at lib/Quelea/App.pm line 23
    #       Quelea::App::BEGIN() called at /path/to/Quelea-Schema/lib/Quelea/Schema.pm line 0
    #       eval {...} called at /path/to/Quelea-Schema/lib/Quelea/Schema.pm line 0
    #       require Quelea/App.pm called at /usr/local/lib/perl/5.10.0/Class/MOP.pm line 98
    #       Class::MOP::__ANON__() called at /usr/local/share/perl/5.10.0/Try/Tiny.pm line 42
    #       eval {...} called at /usr/local/share/perl/5.10.0/Try/Tiny.pm line 39
    #  ...

    my @keys = qw/id code pcode func l_limit u_limit length/;

    for(split /\n/, $SYM_INFO) {
        next if(/^#/);

        my @row = split /\s+/;

        next if(@row != 7);

        my $key = join ",", $row[1], $row[2];
        my $id  = $row[0];

        $FROM_CODE{$key} = { map { $_ => shift @row } @keys };
        push @{ $FROM_ID{$id} }, $FROM_CODE{$key};
    }
}

1;
