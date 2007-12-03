
#==========================
package DOCSIS::ConfigFile;
#==========================

use strict;
use warnings;
use Data::Dumper;
use Digest::MD5;
use Digest::HMAC_MD5;
use DOCSIS::ConfigFile::Decode;
use DOCSIS::ConfigFile::Encode;
use File::Basename;

our $VERSION       = '0.1';
our $DEBUG         = 5;
our %BYTE_SIZE     = (
                        'short int'   => 2,
                        'int'         => 4,
                        'long int'    => 4,
                        'char'        => 1,
                        'float'       => 4,
                        'double'      => 8,
                        'long double' => 12,
                        'md5digest'   => 16,
                     );
our @cmts_mic_list = (
                         1,   2,  3,  4, 17, 43,  6,
                         18, 19, 20, 22, 23, 24, 25,
                         28, 29, 26, 35, 36, 37, 40,
                     );
our @SYMBOL_TABLE  = (
#================================================================================
# ID                           CODE  PCODE  FUNC           L_LIMIT   H_LIMIT    #
# identifier            docsis_code    pID  func           low_limit high_limit #
#================================================================================
[ "Pad",                           0,   0,  '',            0,        0          ],
[ "DownstreamFrequency",           1,   0,  'uint',        88000000, 860000000  ],
[ "UpstreamChannelId",             2,   0,  'uchar',       0,        255        ],
[ "NetworkAccess",                 3,   0,  'uchar',       0,        1          ],
[ "CmMic",                         6,   0,  '',            0,        0          ],
[ "CmtsMic",                       7,   0,  '',            0,        0          ],
[ "ClassOfService",                4,   0,  'aggregate',   0,        0          ],
[ "ClassID",                       1,   4,  'uchar',       1,        16         ],
[ "MaxRateDown",                   2,   4,  'uint',        0,        52000000   ],
[ "MaxRateUp",                     3,   4,  'uint',        0,        10000000   ],
[ "PriorityUp",                    4,   4,  'uchar',       0,        7          ],
[ "GuaranteedUp",                  5,   4,  'uint',        0,        10000000   ],
[ "MaxBurstUp",                    6,   4,  'ushort',      0,        65535      ],
[ "PrivacyEnable",                 7,   4,  'uchar',       0,        1          ],
[ "SwUpgradeFilename",             9,   0,  'string',      0,        0          ],
[ "SnmpWriteControl",             10,   0,  'aggregate',   0,        0          ],
[ "SnmpMibObject",                11,   0,  'snmp_object', 0,        0          ],
[ "CpeMacAddress",                14,   0,  'ether',       0,        0          ],
[ "BaselinePrivacy",              17,   0,  'aggregate',   0,        0          ],
[ "AuthTimeout",                   1,  17,  'uint',        1,        30         ],
[ "ReAuthTimeout",                 2,  17,  'uint',        1,        30         ],
[ "AuthGraceTime",                 3,  17,  'uint',        1,        6047999    ],
[ "OperTimeout",                   4,  17,  'uint',        1,        10         ],
[ "ReKeyTimeout",                  5,  17,  'uint',        1,        10         ],
[ "TEKGraceTime",                  6,  17,  'uint',        1,        302399     ],
[ "AuthRejectTimeout",             7,  17,  'uint',        1,        600        ],
[ "MaxCPE",                       18,   0,  'uchar',       1,        254        ],
[ "SwUpgradeServer",              21,   0,  'ip',          0,        0          ],

 # DOCSIS 1.1-2.0

[ "UsPacketClass",                22,   0,  'aggregate',   0,        0          ],
[ "ClassifierRef",                 1,  22,  'uchar',       1,        255        ],
[ "ClassifierId",                  2,  22,  'ushort',      1,        65535      ],
[ "ServiceFlowRef",                3,  22,  'ushort',      1,        65535      ],
[ "ServiceFlowId",                 4,  22,  'uint',        1,        0xFFFFFFFF ],
[ "RulePriority",                  5,  22,  'uchar',       0,        255        ],
[ "ActivationState",               6,  22,  'uchar',       0,        1          ],
[ "DscAction",                     7,  22,  'uchar',       0,        2          ],
[ "IpPacketClassifier",            9,  22,  'aggregate',   0,        0          ],
[ "IpTos",                         1,   9,  'hexstr',      3,        3          ],
[ "IpProto",                       2,   9,  'ushort',      0,        257        ],
[ "IpSrcAddr",                     3,   9,  'ip',          0,        0          ],
[ "IpSrcMask",                     4,   9,  'ip',          0,        0          ],
[ "IpDstAddr",                     5,   9,  'ip',          0,        0          ],
[ "IpDstMask",                     6,   9,  'ip',          0,        0          ],
[ "SrcPortStart",                  7,   9,  'ushort',      0,        65535      ],
[ "SrcPortEnd",                    8,   9,  'ushort',      0,        65535      ],
[ "DstPortStart",                  9,   9,  'ushort',      0,        65535      ],
[ "DstPortEnd",                   10,   9,  'ushort',      0,        65535      ],
[ "LLCPacketClassifier",          10,  22,  'aggregate',   0,        0          ],
[ "DstMacAddress",                 1,  10,  'ether',       0,        0          ],
[ "SrcMacAddress",                 2,  10,  'ether',       0,        0          ],
[ "EtherType",                     3,  10,  'hexstr',      0,        0          ],
[ "IEEE 802Classifier",           11,  22,  'aggregate',   0,        0          ],
[ "UserPriority",                  1,  11,  'ushort',      0,        0          ],
[ "VlanID",                        2,  11,  'ushort',      0,        0          ],

 # TODO: Vendor Specific support in the IEEE802Classifier

[ "DsPacketClass",                23,   0,  'aggregate',   0,        0          ],
[ "ClassifierRef",                 1,  23,  'uchar',       1,        255        ],
[ "ClassifierId",                  2,  23,  'ushort',      1,        65535      ],
[ "ServiceFlowRef",                3,  23,  'ushort',      1,        65535      ],
[ "ServiceFlowId",                 4,  23,  'uint',        1,        0xFFFFFFFF ],
[ "RulePriority",                  5,  23,  'uchar',       0,        255        ],
[ "ActivationState",               6,  23,  'uchar',       0,        1          ],
[ "DscAction",                     7,  23,  'uchar',       0,        2          ],
[ "IpPacketClassifier",            9,  23,  'aggregate',   0,        0          ],
[ "IpTos",                         1,   9,  'hexstr',      3,        3          ],
[ "IpProto",                       2,   9,  'ushort',      0,        257        ],
[ "IpSrcAddr",                     3,   9,  'ip',          0,        0          ],
[ "IpSrcMask",                     4,   9,  'ip',          0,        0          ],
[ "IpDstAddr",                     5,   9,  'ip',          0,        0          ],
[ "IpDstMask",                     6,   9,  'ip',          0,        0          ],
[ "SrcPortStart",                  7,   9,  'ushort',      0,        65535      ],
[ "SrcPortEnd",                    8,   9,  'ushort',      0,        65535      ],
[ "DstPortStart",                  9,   9,  'ushort',      0,        65535      ],
[ "DstPortEnd",                   10,   9,  'ushort',      0,        65535      ],
[ "LLCPacketClassifier",          10,  23,  'aggregate',   0,        0          ],
[ "DstMacAddress",                 1,  10,  'ether',       0,        0          ],
[ "SrcMacAddress",                 2,  10,  'ether',       0,        0          ],
[ "EtherType",                     3,  10,  'hexstr',      0,        255        ],
[ "IEEE802Classifier",            11,  23,  'aggregate',   0,        0          ],
[ "UserPriority",                  1,  11,  'ushort',      0,        0          ],
[ "VlanID",                        2,  11,  'ushort',      0,        0          ],

 # Upstream Service Flow

[ "UsServiceFlow",                24,   0,  'aggregate',   0,        0          ],
[ "UsServiceFlowRef",              1,  24,  'ushort',      1,        65535      ],
[ "UsServiceFlowId",               2,  24,  'uint',        1,        0xFFFFFFFF ],
[ "ServiceClassName",              4,  24,  'strzero',     2,        16         ],
[ "QosParamSetType",               6,  24,  'uchar',       0,        255        ],
[ "TrafficPriority",               7,  24,  'uchar',       0,        7          ],
[ "MaxRateSustained",              8,  24,  'uint',        0,        0          ],
[ "MaxTrafficBurst",               9,  24,  'uint',        0,        0          ],
[ "MinReservedRate",              10,  24,  'uint',        0,        0          ],
[ "MinResPacketSize",             11,  24,  'ushort',      0,        65535      ],
[ "ActQosParamsTimeout",          12,  24,  'ushort',      0,        65535      ],
[ "AdmQosParamsTimeout",          13,  24,  'ushort',      0,        65535      ],

 # Upstream Service Flow Specific params

[ "MaxConcatenatedBurst",         14,  24,  'ushort',      0,        65535      ],
[ "SchedulingType",               15,  24,  'uchar',       0,        6          ],
[ "RequestOrTxPolicy",            16,  24,  'hexstr',      4,        4          ],
[ "NominalPollInterval",          17,  24,  'uint',        0,        0          ],
[ "ToleratedPollJitter",          18,  24,  'uint',        0,        0          ],
[ "UnsolicitedGrantSize",         19,  24,  'ushort',      0,        65535      ],
[ "NominalGrantInterval",         20,  24,  'uint',        0,        0          ],
[ "ToleratedGrantJitter",         21,  24,  'uint',        0,        0          ],
[ "GrantsPerInterval",            22,  24,  'uchar',       0,        127        ],
[ "IpTosOverwrite",               23,  24,  'hexstr',      2,        2          ],

  # Downstream Service Flow

[ "DsServiceFlow",                25,   0,  'aggregate',   0,        0          ],
[ "DsServiceFlowRef",              1,  25,  'ushort',      1,        65535      ],
[ "DsServiceFlowId",               2,  25,  'uint',        1,        0xFFFFFFFF ],
[ "ServiceClassName",              4,  25,  'strzero',     2,        16         ],
[ "QosParamSetType",               6,  25,  'uchar',       0,        255        ],
[ "TrafficPriority",               7,  25,  'uchar',       0,        7          ],
[ "MaxRateSustained",              8,  25,  'uint',        0,        0xFFFFFFFF ],
[ "MaxTrafficBurst",               9,  25,  'uint',        0,        0xFFFFFFFF ],
[ "MinReservedRate",              10,  25,  'uint',        0,        0xFFFFFFFF ],
[ "MinResPacketSize",             11,  25,  'ushort',      0,        65535      ],
[ "ActQosParamsTimeout",          12,  25,  'ushort',      0,        65535      ],
[ "AdmQosParamsTimeout",          13,  25,  'ushort',      0,        65535      ],

  # Downstream Service Flow Specific Params

[ "MaxDsLatency",                 14,  25,  'uint',        0,        0          ],

  # Payload Header Suppression - Appendix C.2.2.8

[ "PHS",                          26,   0,  'aggregate',   0,        0          ],
[ "PHSClassifierRef",              1,  26,  'uchar',       1,        255        ],
[ "PHSClassifierId",               2,  26,  'ushort',      1,        65535      ],
[ "PHSServiceFlowRef",             3,  26,  'ushort',      1,        65535      ],
[ "PHSServiceFlowId",              4,  26,  'uint',        1,        0xFFFFFFFF ],

  # Payload Header Suppression Rule - Appendix C.2.2.10

[ "PHSField",                      7,  26,  'hexstr',      1,        255        ],
[ "PHSIndex",                      8,  26,  'uchar',       1,        255        ],
[ "PHSMask",                       9,  26,  'hexstr',      1,        255        ],
[ "PHSSize",                      10,  26,  'uchar',       1,        255        ],
[ "PHSVerify",                    11,  26,  'uchar',       0,        1          ],
[ "MaxClassifiers",               28,   0,  'ushort',      0,        0          ],
[ "GlobalPrivacyEnable",          29,   0,  'uchar',       0,        0          ],

  # BPI+ SubTLV  's

[ "SAMapWaitTimeout",              8,  17,  'uint',        1,        10         ],
[ "SAMapMaxRetries",               9,  17,  'uint',        0,        10         ],

  # ManufacturerCVC

[ "MfgCVCData",                   32,   0,  'hexstr',      0,        255        ],

  # Vendor Specific

[ "VendorSpecific",               43,   0,  'vendorspec',  0,        0          ],
[ "VendorIdentifier",              8,  43,  'hexstr',      3,        3          ],

  # SNMPv3 Kickstart

[ "SnmpV3Kickstart",              34,   0,  'aggregate',   0,        0          ],

  # TODO: SP-RFI-v2.0 says the SecurityName is UTF8 encoded

[ "SnmpV3SecurityName",            1,  34,  'string',      1,        16         ],
[ "SnmpV3MgrPublicNumber",         2,  34,  'hexstr',      1,        514        ],

  # Snmpv3 Notification Receiver

[ "SnmpV3TrapReceiver",           38,   0,  'aggregate',   0,        0          ],
[ "SnmpV3TrapRxIP",                1,  38,  'ip',          0,        0          ],
[ "SnmpV3TrapRxPort",              2,  38,  'ushort',      0,        0          ],
[ "SnmpV3TrapRxType",              3,  38,  'ushort',      1,        5          ],
[ "SnmpV3TrapRxTimeout",           4,  38,  'ushort',      0,        65535      ],
[ "SnmpV3TrapRxRetries",           5,  38,  'ushort',      0,        65535      ],
[ "SnmpV3TrapRxFilterOID",         6,  38,  'oid',         1,        5          ],
[ "SnmpV3TrapRxSecurityName",      7,  38,  'string',      1,        16         ],
[ "DocsisTwoEnable",              39,   0,  'uchar',       0,        1          ],

  # Modem Capabilities Encodings

[ "ModemCapabilities",             5,   0,  'aggregate',   0,        0          ],
[ "ConcatenationSupport",          1,   5,  'uchar',       0,        1          ],
[ "ModemDocsisVersion",            2,   5,  'uchar',       0,        2          ],
[ "FragmentationSupport",          3,   5,  'uchar',       0,        1          ],
[ "PHSSupport",                    4,   5,  'uchar',       0,        1          ],
[ "IGMPSupport",                   5,   5,  'uchar',       0,        1          ],
[ "BaselinePrivacySupport",        6,   5,  'uchar',       0,        1          ],
[ "DownstreamSAIDSupport",         7,   5,  'uchar',       0,        255        ],
[ "UpstreamSIDSupport",            8,   5,  'uchar',       0,        255        ],
[ "DCCSupport",                   12,   5,  'uchar',       0,        1          ],
[ "SubMgmtControl",               35,   0,  'hexstr',      3,        3          ],
[ "SubMgmtFilters",               37,   0,  'ushort_list', 4,        4          ],
[ "SnmpMibObject",                64,   0,  'aggregate',   1,        2048       ],

  # PacketCable MTA Configuration File Delimiter

[ "MtaConfigDelimiter",          254,   0,  'uchar',       1,        255        ],
[ "DsChannelList",                41,   0,  'aggregate',   1,        255        ],
[ "SingleDsChannel",               1,  41,  'aggregate',   1,        255        ],
[ "SingleDsTimeout",               1,   1,  'ushort',      0,        65535      ],
[ "SingleDsFrequency",             2,   1,  'uint',        0,        0xFFFFFFFF ],
[ "DsFreqRange",                   2,  41,  'aggregate',   1,        255        ],
[ "DsFreqRangeTimeout",            1,   2,  'ushort',      0,        65535      ],
[ "DsFreqRangeStart",              2,   2,  'uint',        0,        0xFFFFFFFF ],
[ "DsFreqRangeEnd",                3,   2,  'uint',        0,        0xFFFFFFFF ],
[ "DsFreqRangeStepSize",           4,   2,  'uint',        0,        0xFFFFFFFF ],
[ "DefaultScanTimeout",            3,  41,  'ushort',      0,        65535      ],
[ "TftpTimestamp",                19,   0,  'uint',        0,        0xFFFFFFFF ],
[ "TftpModemAddress",             20,   0,  'ip',          0,        0          ],

  # Generic TLV ... we only use the limits ,  code and length don  't matter ...

[ "GenericTLV",                    0,   0,  'aggregate',   1,        255        ],
[ "GenericTLV",                  255,   0,  '',            0,        0          ],
);


sub ID      { 0 }
sub CODE    { 1 }
sub PCODE   { 2 }
sub FUNC    { 3 }
sub L_LIMIT { 4 }
sub U_LIMIT { 5 }

sub new { #===================================================================

    ### init
    my $class  = shift;
    my $self   = bless {
                    filehandle    => '',
                    read_file     => '',
                    write_file    => '',
                    binstring     => '',
                    shared_secret => '',
                    @_,
                 }, $class;

    ### mib
    $ENV{'MIBS'} = "ALL";
    #$self->init_mib;

    ### the end
    return $self;
}

sub decode { #================================================================

    ### init
    my $self = ref $_[0] ? shift(@_) : new(shift(@_), @_);
    my %args = @_;
    my $FH;

    ### setup args
    $self->{$_} = $args{$_} for(keys %args);

    ### no filehandle
    unless(ref $self->{'filehandle'} eq 'GLOB') {

        ### read from file on disk
        if($self->{'read_file'} and -r $self->{'read_file'}) {
            open($FH, '<', $self->{'read_file'}) or die $!;
            binmode $FH;
            $self->{'filehandle'} = $FH;
        }

        ### read from string
        elsif($self->{'binstring'}) {
            open($FH, '<', \$self->{'binstring'});
            binmode $FH;
            $self->{'filehandle'} = $FH;
        }
    }

    ### still no filehandle
    unless(ref $FH eq 'GLOB') {
        warn "No valid filename, binstring or filehandle\n" if($DEBUG);
        return;
    }

    ### the end
    return $self->_decode_loop;
}

sub _decode_loop { #==========================================================

    ### init
    my $self         = shift;
    my $total_length = shift || 0xffffffff;
    my $pID          = shift || 0;
    my $FH           = $self->{'filehandle'};
    my $cfg          = [];
    my($syminfo, $value);

    BYTE:
    while($total_length > 0) {

        ### read data header
        sysread($FH, my $code,   1) or last BYTE;
        sysread($FH, my $length, 1) or last BYTE;

        $code          = unpack("C", $code);
        $length        = unpack("C", $length) or next BYTE;
        $syminfo       = $self->find_syminfo($code, $pID);
        $value         = '';
        $total_length -= $length + 2;

        ### nested block
        if($syminfo->[&FUNC] eq 'aggregate') {
            my $aggregate = $self->_decode_loop($length, $syminfo->[&CODE]);
            push @$cfg, _value_to_cfg($syminfo, $length, undef, $aggregate);
            next BYTE;
        }

        ### normal
        sysread($FH, my $data, $length);
        my $aggregate;

        ### decode binary string
        if(my $sub = DOCSIS::ConfigFile::Decode->can($syminfo->[&FUNC])) {
            ($value, $aggregate) = $sub->($data);
            unless(defined $value) {
                next BYTE;
            }
        }
        else {
            @{$syminfo}[0,1,3] = ('NA', $code, 'unpack(H*)');
            $value             = DOCSIS::ConfigFile::Decode::hexstr($data);
        }

        ### do something with the result
        push @$cfg, _value_to_cfg($syminfo, $length, $value, $aggregate); 
    }

    ### the end
    return $cfg;
}

sub _value_to_cfg { #=========================================================

    ### init
    my $syminfo   = shift;
    my $length    = shift;
    my $value     = shift;
    my $aggregate = shift;

    ### the end
    return {
        name   => $syminfo->[&ID],
        code   => $syminfo->[&CODE],
        pcode  => $syminfo->[&PCODE],
        func   => $syminfo->[&FUNC],
        llimit => $syminfo->[&L_LIMIT],
        ulimit => $syminfo->[&U_LIMIT],
        length => $length,
        (defined $value ? (value     => $value    ) : ()),
        ($aggregate     ? (aggregate => $aggregate) : ()),
    };
}

sub encode { #================================================================

    ### init
    my $self = ref $_[0] ? shift(@_) : new(shift(@_), @_);
    my %args = @_;
    my $config;

    ### setup args
    $self->{$_} = $args{$_} for(keys %args);
    $config     = $self->{'config'};

    ### check config
    unless(ref $config eq 'ARRAY') {
        return;
    }

    ### init cmts mic calculation
    $self->{'cmts_mic_data'}{$_} = [] for(@cmts_mic_list);

    ### encode data
    $self->{'binstring'} = $self->_encode_loop($config);

    ### cm file
    unless(grep { $_->{'name'} eq 'MtaConfigDelimiter' } @$config) {

        ### calculate mic, eod and pad
        my $cm_mic   = $self->calculate_cm_mic;
        my $cmts_mic = $self->calculate_cmts_mic($cm_mic);
        my $eod_pad  = $self->calculate_eod_and_pad;

        ### add mic, eod and pad
        $self->{'binstring'} .= $cm_mic .$cmts_mic. $eod_pad;
    }

    ### save to disk
    if($self->{'write_file'} and -w dirname($self->{'write_file'})) {
        open(my $FH, '>', $self->{'write_file'}) or die $!;
        binmode $FH;
        syswrite($FH, $self->{'binstring'});
        close $FH;
    }

    ### the end
    return $self->{'binstring'};
}

sub _encode_loop { #==========================================================

    ### init
    my $self      = shift;
    my $config    = shift;
    my $level     = shift || 0;
    my $binstring = '';

    ### check config
    unless(ref $config eq 'ARRAY') {
        warn "Not an array: " .ref($config) ."\n";
        return "";
    }

    TLV:
    for my $tlv (@$config) {

        ### init
        my $name    = $tlv->{'name'} or next TLV;
        my $syminfo = $self->find_syminfo($name);
        my $sub     = DOCSIS::ConfigFile::Encode->can($syminfo->[&FUNC]);
        my $code    = $syminfo->[&CODE];

        ### nested tlv
        if($syminfo->[&FUNC] eq 'aggregate') {

            ### set binstring
            my $value   = $self->_encode_loop($tlv->{'aggregate'}, $level+1);
            my $length  = pack "C", length $value;
            my $type    = pack "C", $code;
            $binstring .= $type .$length .$value;

            ### add to cmts mic calculation
            if(!$level and exists $self->{'cmts_mic_data'}{$code}) {
                push @{ $self->{'cmts_mic_data'}{$code} },
                     $type .$length .$value;
            }

            ### skip ahead
            next TLV;
        }

        ### don't know what to do
        elsif(not $sub) {
            next TLV;
        }

        ### check value range
        if($syminfo->[&L_LIMIT] or $syminfo->[&U_LIMIT]) {
            my $value = ($tlv->{'value'} =~ /\D/) ? hex $tlv->{'value'}
                      :                                 $tlv->{'value'};
            if($value > $syminfo->[&U_LIMIT]) {
                next TLV;
            }
            if($value < $syminfo->[&L_LIMIT]) {
                next TLV;
            }
        }

        ### set type, length and value
        my @value  = $sub->($tlv);
        my $type   = pack "C", $syminfo->[&CODE];
        my $length = pack "C", int(@value);
        my $value  = pack "C*", @value;

        ### check value length
        if(length $value > 255) {
            next TLV;
        }

        ### save data to binstring
        $binstring .= "$type$length$value";

        ### add to cmts mic calculation
        if(!$level and exists $self->{'cmts_mic_data'}{$code}) {
            push @{ $self->{'cmts_mic_data'}{$code} },
                 $type .$length .$value;
        }
    }

    ### the end
    return $binstring;
}

sub find_syminfo { #==========================================================

    ### init
    my $self  = shift;
    my $code  = shift || 0;
    my $pID   = shift || 0;
    my $row   = [-1, '', -1, -1, '', '', 0, 0];

    ### no code to figure out
    return $row unless($code);

    ### numeric lookup
    if($code =~ /^\d+$/) {
        for(@SYMBOL_TABLE) {
            next unless($_->[&CODE]  == $code);
            next unless($_->[&PCODE] == $pID);
            $row = $_;
            last;
        }
    }

    ### name lookup
    else {
        for(@SYMBOL_TABLE) {
            next unless($_->[&ID] eq $code);
            $row = $_;
            last;
        }
    }

    ### the end
    return $row;
}

sub calculate_eod_and_pad { #=================================================

    ### init
    my $self = shift;
    my $pads = 4 - (1 + length $self->{'binstring'}) % 4;

    ### the end
    return pack("C", 255) .("\0" x $pads);
}

sub calculate_cm_mic { #======================================================

    ### init
    my $self   = shift;
    my $cm_mic = pack("C*", 6, 16) .Digest::MD5::md5($self->{'binstring'});

    ### save to cmts_mic_data
    $self->{'cmts_mic_data'}{6} = [$cm_mic];

    ### the end
    return $cm_mic;
}

sub calculate_cmts_mic { #====================================================

    ### init
    my $self          = shift;
    my $cm_mic        = shift;
    my $shared_secret = $self->{'shared_secret'} || '';
    my $cmts_mic_data = $self->{'cmts_mic_data'};
    my $data          = "";

    ### re-arrage data
    for my $k (@cmts_mic_list) {
        for my $d (@{ $cmts_mic_data->{$k} }) {
            $data .= $d;
        }
    }

    ### the end
    return pack("C*", 7, 16)
          .Digest::HMAC_MD5::hmac_md5($data, $shared_secret)
          ;
}

#=============================================================================
1983;
__END__

=head1 NAME

DOCSIS::ConfigFile - Decodes and encodes DOCSIS config-files for cable-modems

=head1 VERSION

Version 0.1

=head1 SYNOPSIS

    use DOCSIS::ConfigFile;

    my $obj = DOCSIS::ConfigFile->new(
                  filehandle    => '', # used by decode
                  read_file     => '', # used by decode
                  write_file    => '', # used by encode
                  shared_secret => '', # used by encode
                  binstring     => '', # holds the data
              )
 
    $config_data = $obj->encode;
    $config_data = $obj->decode;

=head1 METHODS

=head2 new

Object constructor

=head2 decode

Decodes the config-file.

=head2 encode

Encodes the config-file settings.

=head2 find_syminfo

Returns a array ref with information about the docsis symbol. The symbol can
be either ID or a combination of CODE and PCODE.

=head2 calculate_eod_and_pad

Returns the EOD and padding for the config-file. Called automatically from
inside encode().

=head2 calculate_cm_mic

Returns the CM MIC. Called automatically from inside encode().

=head2 calculate_cmts_mic

Returns the CMTS MIC. Called automatically from inside encode().

=head1 FUNCTIONS

=head2 ID

find_syminfo("foo")->[&ID] returns the identifier for the symbol "foo"

=head2 CODE

find_syminfo("foo")->[&CODE] returns the docsis code for the symbol "foo"

=head2 PCODE

find_syminfo("foo")->[&PCODE] returns the parent docsis code for the symbol

=head2 FUNC

find_syminfo("foo")->[&PCODE] returns the function name to use to enc/decode
the docsis symbol.

=head2 L_LIMIT

find_syminfo("foo")->[&PCODE] returns the lower limit for this value.

=head2 U_LIMIT

find_syminfo("foo")->[&PCODE] returns the upper limit for this value.

=head1 AUTHOR

Jan Henning Thorsen, C<< <pm at flodhest.net> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-docsis-perl at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=DOCSIS-ConfigFile>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc DOCSIS::ConfigFile

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/DOCSIS-ConfigFile>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/DOCSIS-ConfigFile>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=DOCSIS-ConfigFile>

=item * Search CPAN

L<http://search.cpan.org/dist/DOCSIS-ConfigFile>

=back

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

------------------------------------------------------------------------------
THIS PROGRAM IS BASED ON THE C-PROGRAM "docsis" FROM docsis.sf.net!
------------------------------------------------------------------------------

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

Copyright (c) 2007 Jan Henning Thorsen

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

DOCSIS is a registered trademark of Cablelabs, http://www.cablelabs.com

=cut
