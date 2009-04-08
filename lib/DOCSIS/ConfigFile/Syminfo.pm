package DOCSIS::ConfigFile::Syminfo;

=head1 NAME

DOCSIS::ConfigFile::Syminfo - Symbolinfo for a DOCSIS config-file

=head1 VERSION

See DOCSIS::ConfigFile

=head1 SYNOPSIS

 use DOCSIS::ConfigFile::Syminfo;

 my $obj = DOCSIS::ConfigFile::Syminfo->from_id($docsis_symbol);
 my $obj = DOCSIS::ConfigFile::Syminfo->from_code($code, $pcode);

=cut

use strict;
use warnings;
use constant ID      => 0;
use constant CODE    => 1;
use constant PCODE   => 2;
use constant FUNC    => 3;
use constant L_LIMIT => 4;
use constant U_LIMIT => 5;

my @UNDEF_ROW = ("", -1, -1, "", -1, -1);

our @SYMBOL_TABLE = (
#=============================================================================
# ID                        CODE  PCODE  FUNC           L_LIMIT   H_LIMIT
# identifier         docsis_code    pID  func           low_limit high_limit
#=============================================================================
[ "Pad",                       0,   0,  "",            0,        0          ],
[ "DownstreamFrequency",       1,   0,  "uint",        88000000, 860000000  ],
[ "UpstreamChannelId",         2,   0,  "uchar",       0,        255        ],
[ "CmMic",                     6,   0,  "mic",         0,        0          ],
[ "CmtsMic",                   7,   0,  "mic",         0,        0          ],
[ "NetworkAccess",             3,   0,  "uchar",       0,        1          ],
[ "ClassOfService",            4,   0,  "nested",      0,        0          ],
[ "ClassID",                   1,   4,  "uchar",       1,        16         ],
[ "MaxRateDown",               2,   4,  "uint",        0,        52000000   ],
[ "MaxRateUp",                 3,   4,  "uint",        0,        10000000   ],
[ "PriorityUp",                4,   4,  "uchar",       0,        7          ],
[ "GuaranteedUp",              5,   4,  "uint",        0,        10000000   ],
[ "MaxBurstUp",                6,   4,  "ushort",      0,        65535      ],
[ "PrivacyEnable",             7,   4,  "uchar",       0,        1          ],
[ "SwUpgradeFilename",         9,   0,  "string",      0,        0          ],
[ "SnmpWriteControl",         10,   0,  "nested",      0,        0          ],
[ "SnmpMibObject",            11,   0,  "snmp_object", 0,        255        ],
[ "CpeMacAddress",            14,   0,  "ether",       0,        0          ],
[ "BaselinePrivacy",          17,   0,  "nested",      0,        0          ],
[ "AuthTimeout",               1,  17,  "uint",        1,        30         ],
[ "ReAuthTimeout",             2,  17,  "uint",        1,        30         ],
[ "AuthGraceTime",             3,  17,  "uint",        1,        6047999    ],
[ "OperTimeout",               4,  17,  "uint",        1,        10         ],
[ "ReKeyTimeout",              5,  17,  "uint",        1,        10         ],
[ "TEKGraceTime",              6,  17,  "uint",        1,        302399     ],
[ "AuthRejectTimeout",         7,  17,  "uint",        1,        600        ],
[ "MaxCPE",                   18,   0,  "uchar",       1,        254        ],
[ "SwUpgradeServer",          21,   0,  "ip",          0,        0          ],

 # DOCSIS 1.1-2.0

[ "UsPacketClass",            22,   0,  "nested",      0,        0          ],
[ "ClassifierRef",             1,  22,  "uchar",       1,        255        ],
[ "ClassifierId",              2,  22,  "ushort",      1,        65535      ],
[ "ServiceFlowRef",            3,  22,  "ushort",      1,        65535      ],
[ "ServiceFlowId",             4,  22,  "uint",        1,        0xFFFFFFFF ],
[ "RulePriority",              5,  22,  "uchar",       0,        255        ],
[ "ActivationState",           6,  22,  "uchar",       0,        1          ],
[ "DscAction",                 7,  22,  "uchar",       0,        2          ],
[ "IpPacketClassifier",        9,  22,  "nested",      0,        0          ],
[ "IpTos",                     1,   9,  "hexstr",      3,        3          ],
[ "IpProto",                   2,   9,  "ushort",      0,        257        ],
[ "IpSrcAddr",                 3,   9,  "ip",          0,        0          ],
[ "IpSrcMask",                 4,   9,  "ip",          0,        0          ],
[ "IpDstAddr",                 5,   9,  "ip",          0,        0          ],
[ "IpDstMask",                 6,   9,  "ip",          0,        0          ],
[ "SrcPortStart",              7,   9,  "ushort",      0,        65535      ],
[ "SrcPortEnd",                8,   9,  "ushort",      0,        65535      ],
[ "DstPortStart",              9,   9,  "ushort",      0,        65535      ],
[ "DstPortEnd",               10,   9,  "ushort",      0,        65535      ],
[ "LLCPacketClassifier",      10,  22,  "nested",      0,        0          ],
[ "DstMacAddress",             1,  10,  "ether",       0,        0          ],
[ "SrcMacAddress",             2,  10,  "ether",       0,        0          ],
[ "EtherType",                 3,  10,  "hexstr",      0,        0          ],
[ "IEEE 802Classifier",       11,  22,  "nested",      0,        0          ],
[ "UserPriority",              1,  11,  "ushort",      0,        0          ],
[ "VlanID",                    2,  11,  "ushort",      0,        0          ],

 # TODO: Vendor Specific support in the IEEE802Classifier

[ "DsPacketClass",            23,   0,  "nested",      0,        0          ],
[ "ClassifierRef",             1,  23,  "uchar",       1,        255        ],
[ "ClassifierId",              2,  23,  "ushort",      1,        65535      ],
[ "ServiceFlowRef",            3,  23,  "ushort",      1,        65535      ],
[ "ServiceFlowId",             4,  23,  "uint",        1,        0xFFFFFFFF ],
[ "RulePriority",              5,  23,  "uchar",       0,        255        ],
[ "ActivationState",           6,  23,  "uchar",       0,        1          ],
[ "DscAction",                 7,  23,  "uchar",       0,        2          ],
[ "IpPacketClassifier",        9,  23,  "nested",      0,        0          ],
[ "IpTos",                     1,   9,  "hexstr",      3,        3          ],
[ "IpProto",                   2,   9,  "ushort",      0,        257        ],
[ "IpSrcAddr",                 3,   9,  "ip",          0,        0          ],
[ "IpSrcMask",                 4,   9,  "ip",          0,        0          ],
[ "IpDstAddr",                 5,   9,  "ip",          0,        0          ],
[ "IpDstMask",                 6,   9,  "ip",          0,        0          ],
[ "SrcPortStart",              7,   9,  "ushort",      0,        65535      ],
[ "SrcPortEnd",                8,   9,  "ushort",      0,        65535      ],
[ "DstPortStart",              9,   9,  "ushort",      0,        65535      ],
[ "DstPortEnd",               10,   9,  "ushort",      0,        65535      ],
[ "LLCPacketClassifier",      10,  23,  "nested",      0,        0          ],
[ "DstMacAddress",             1,  10,  "ether",       0,        0          ],
[ "SrcMacAddress",             2,  10,  "ether",       0,        0          ],
[ "EtherType",                 3,  10,  "hexstr",      0,        255        ],
[ "IEEE802Classifier",        11,  23,  "nested",      0,        0          ],
[ "UserPriority",              1,  11,  "ushort",      0,        0          ],
[ "VlanID",                    2,  11,  "ushort",      0,        0          ],

 # Upstream Service Flow

[ "UsServiceFlow",            24,   0,  "nested",      0,        0          ],
[ "UsServiceFlowRef",          1,  24,  "ushort",      1,        65535      ],
[ "UsServiceFlowId",           2,  24,  "uint",        1,        0xFFFFFFFF ],
[ "ServiceClassName",          4,  24,  "string",      2,        16         ],
[ "QosParamSetType",           6,  24,  "uchar",       0,        255        ],
[ "TrafficPriority",           7,  24,  "uchar",       0,        7          ],
[ "MaxRateSustained",          8,  24,  "uint",        0,        0          ],
[ "MaxTrafficBurst",           9,  24,  "uint",        0,        0          ],
[ "MinReservedRate",          10,  24,  "uint",        0,        0          ],
[ "MinResPacketSize",         11,  24,  "ushort",      0,        65535      ],
[ "ActQosParamsTimeout",      12,  24,  "ushort",      0,        65535      ],
[ "AdmQosParamsTimeout",      13,  24,  "ushort",      0,        65535      ],

 # Upstream Service Flow Specific params

[ "MaxConcatenatedBurst",     14,  24,  "ushort",      0,        65535      ],
[ "SchedulingType",           15,  24,  "uchar",       0,        6          ],
[ "RequestOrTxPolicy",        16,  24,  "hexstr",      0,        255        ],
[ "NominalPollInterval",      17,  24,  "uint",        0,        0          ],
[ "ToleratedPollJitter",      18,  24,  "uint",        0,        0          ],
[ "UnsolicitedGrantSize",     19,  24,  "ushort",      0,        65535      ],
[ "NominalGrantInterval",     20,  24,  "uint",        0,        0          ],
[ "ToleratedGrantJitter",     21,  24,  "uint",        0,        0          ],
[ "GrantsPerInterval",        22,  24,  "uchar",       0,        127        ],
[ "IpTosOverwrite",           23,  24,  "hexstr",      0,        255        ],

  # Downstream Service Flow

[ "DsServiceFlow",            25,   0,  "nested",      0,        0          ],
[ "DsServiceFlowRef",          1,  25,  "ushort",      1,        65535      ],
[ "DsServiceFlowId",           2,  25,  "uint",        1,        0xFFFFFFFF ],
[ "ServiceClassName",          4,  25,  "string",      2,        16         ],
[ "QosParamSetType",           6,  25,  "uchar",       0,        255        ],
[ "TrafficPriority",           7,  25,  "uchar",       0,        7          ],
[ "MaxRateSustained",          8,  25,  "uint",        0,        0xFFFFFFFF ],
[ "MaxTrafficBurst",           9,  25,  "uint",        0,        0xFFFFFFFF ],
[ "MinReservedRate",          10,  25,  "uint",        0,        0xFFFFFFFF ],
[ "MinResPacketSize",         11,  25,  "ushort",      0,        65535      ],
[ "ActQosParamsTimeout",      12,  25,  "ushort",      0,        65535      ],
[ "AdmQosParamsTimeout",      13,  25,  "ushort",      0,        65535      ],

  # Downstream Service Flow Specific Params

[ "MaxDsLatency",             14,  25,  "uint",        0,        0          ],

  # Payload Header Suppression - Appendix C.2.2.8

[ "PHS",                      26,   0,  "nested",      0,        0          ],
[ "PHSClassifierRef",          1,  26,  "uchar",       1,        255        ],
[ "PHSClassifierId",           2,  26,  "ushort",      1,        65535      ],
[ "PHSServiceFlowRef",         3,  26,  "ushort",      1,        65535      ],
[ "PHSServiceFlowId",          4,  26,  "uint",        1,        0xFFFFFFFF ],

  # Payload Header Suppression Rule - Appendix C.2.2.10

[ "PHSField",                  7,  26,  "hexstr",      1,        255        ],
[ "PHSIndex",                  8,  26,  "uchar",       1,        255        ],
[ "PHSMask",                   9,  26,  "hexstr",      1,        255        ],
[ "PHSSize",                  10,  26,  "uchar",       1,        255        ],
[ "PHSVerify",                11,  26,  "uchar",       0,        1          ],
[ "MaxClassifiers",           28,   0,  "ushort",      0,        0          ],
[ "GlobalPrivacyEnable",      29,   0,  "uchar",       0,        0          ],

  # BPI+ SubTLV  "s

[ "SAMapWaitTimeout",          8,  17,  "uint",        1,        10         ],
[ "SAMapMaxRetries",           9,  17,  "uint",        0,        10         ],

  # ManufacturerCVC

[ "MfgCVCData",               32,   0,  "hexstr",      0,        0          ],

  # Vendor Specific

[ "VendorSpecific",           43,   0,  "vendorspec",  0,        0          ],
[ "VendorIdentifier",          8,  43,  "hexstr",      3,        3          ],

  # SNMPv3 Kickstart

[ "SnmpV3Kickstart",          34,   0,  "nested",      0,        0          ],

  # TODO: SP-RFI-v2.0 says the SecurityName is UTF8 encoded

[ "SnmpV3SecurityName",        1,  34,  "string",      1,        16         ],
[ "SnmpV3MgrPublicNumber",     2,  34,  "hexstr",      1,        514        ],

  # Snmpv3 Notification Receiver

[ "SnmpV3TrapReceiver",       38,   0,  "nested",      0,        0          ],
[ "SnmpV3TrapRxIP",            1,  38,  "ip",          0,        0          ],
[ "SnmpV3TrapRxPort",          2,  38,  "ushort",      0,        0          ],
[ "SnmpV3TrapRxType",          3,  38,  "ushort",      1,        5          ],
[ "SnmpV3TrapRxTimeout",       4,  38,  "ushort",      0,        65535      ],
[ "SnmpV3TrapRxRetries",       5,  38,  "ushort",      0,        65535      ],
[ "SnmpV3TrapRxFilterOID",     6,  38,  "ushort",      1,        5          ],
[ "SnmpV3TrapRxSecurityName",  7,  38,  "string",      1,        16         ],
[ "DocsisTwoEnable",          39,   0,  "uchar",       0,        1          ],

  # Modem Capabilities Encodings

[ "ModemCapabilities",         5,   0,  "nested",      0,        0          ],
[ "ConcatenationSupport",      1,   5,  "uchar",       0,        1          ],
[ "ModemDocsisVersion",        2,   5,  "uchar",       0,        2          ],
[ "FragmentationSupport",      3,   5,  "uchar",       0,        1          ],
[ "PHSSupport",                4,   5,  "uchar",       0,        1          ],
[ "IGMPSupport",               5,   5,  "uchar",       0,        1          ],
[ "BaselinePrivacySupport",    6,   5,  "uchar",       0,        1          ],
[ "DownstreamSAIDSupport",     7,   5,  "uchar",       0,        255        ],
[ "UpstreamSIDSupport",        8,   5,  "uchar",       0,        255        ],
[ "DCCSupport",               12,   5,  "uchar",       0,        1          ],
[ "SubMgmtControl",           35,   0,  "hexstr",      3,        3          ],
[ "SubMgmtCpeTable",          36,   0,  "hexstr",      0,        0          ],
[ "SubMgmtFilters",           37,   0,  "ushort_list", 4,        4          ],
[ "SnmpMibObject64",          64,   0,  "snmp_object", 1,        65535      ],
[ "TestMode",                 40,   0,  "hexstr",      0,        1          ],

  # PacketCable MTA Configuration File Delimiter

[ "MtaConfigDelimiter",      254,   0,  "uchar",       1,        255        ],
[ "DsChannelList",            41,   0,  "nested",      1,        255        ],
[ "SingleDsChannel",           1,  41,  "nested",      1,        255        ],
[ "SingleDsTimeout",           1,   1,  "ushort",      0,        65535      ],
[ "SingleDsFrequency",         2,   1,  "uint",        0,        0xFFFFFFFF ],
[ "DsFreqRange",               2,  41,  "nested",      1,        255        ],
[ "DsFreqRangeTimeout",        1,   2,  "ushort",      0,        65535      ],
[ "DsFreqRangeStart",          2,   2,  "uint",        0,        0xFFFFFFFF ],
[ "DsFreqRangeEnd",            3,   2,  "uint",        0,        0xFFFFFFFF ],
[ "DsFreqRangeStepSize",       4,   2,  "uint",        0,        0xFFFFFFFF ],
[ "DefaultScanTimeout",        3,  41,  "ushort",      0,        65535      ],
[ "TftpTimestamp",            19,   0,  "uint",        0,        0xFFFFFFFF ],
[ "TftpModemAddress",         20,   0,  "ip",          0,        0          ],

  # Generic TLV... we only use the limits, code and length don"t matter

[ "GenericTLV",                0,   0,  "nested",      1,        255        ],
[ "GenericTLV",              255,   0,  "",            0,        0          ],
);

=head1 METHODS

=head2 from_id

Arguments:

 * 'identifier' => Name of the DOCSIS symbol

Returns a C<DOCSIS::ConfigFile::Syminfo> object.

=cut

sub from_id {
    my $class = shift;
    my $id    = shift;
    my $row   = [@UNDEF_ROW];

    return $row unless(defined $id);

    for(@SYMBOL_TABLE) {
        next unless($_->[ID] eq $id);
        @$row = @$_;
        last;
    }

    return bless $row, $class;
}

=head2 from_code

Arguments:

 * $code  => The DOCSIS code
 * $pcode => If it's a sub-symbol

Returns a C<DOCSIS::ConfigFile::Syminfo> object.

=cut

sub from_code {
    my $class = shift;
    my $code  = shift;
    my $pID   = shift || 0;
    my $row   = [@UNDEF_ROW];

    return $row unless(defined $code);

    for(@SYMBOL_TABLE) {
        next unless($_->[CODE]  == $code);
        next unless($_->[PCODE] == $pID);
        @$row = @$_;
        last;
    }

    return bless $row, $class;
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

=cut

BEGIN {
    no strict 'refs';
    my %sub2index = (
        id      => ID,
        code    => CODE,
        pcode   => PCODE,
        func    => FUNC,
        l_limit => L_LIMIT,
        u_limit => U_LIMIT,
    );

    for my $sub (keys %sub2index) {
        my $key = $sub2index{$sub};
        *$sub   = sub { return shift->[$key] };
    }
}

=head2 fallback_values

Sets some default values on the current object.

=cut

sub fallback_values {
    my $self   = shift;
    my $code   = shift;
    my $p_code = shift;

    $self->[ID]    = '';
    $self->[CODE]  = $code;
    $self->[PCODE] = $p_code;
    $self->[FUNC]  = 'hexstr';
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

1;
