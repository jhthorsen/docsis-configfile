use strict;
use warnings;
use Test::More;
use DOCSIS::ConfigFile;

#$DOCSIS::ConfigFile::TRACE = 1;

my $original = config();
my $docsis   = DOCSIS::ConfigFile->new;
my $encoded  = $docsis->encode($original);
my $decoded  = $docsis->decode(\$encoded);
my $i        = 0;

plan tests => scalar(@$original);

for my $o (@$original) {
    is($decoded->[$i]->{'name'}, $o->{'name'}, "$o->{'name'} is ok");
    $i++;
}

sub config {
    return [
          {
            'name'  => 'NetworkAccess',
            'value' => '1',
          },
          {
            'name'  => 'GlobalPrivacyEnable',
            'value' => '1',
          },
          {
            'name'  => 'MaxCPE',
            'value' => '10',
          },
          {
            'name'  => 'BaselinePrivacy',
            'nested' => [
                             {
                               'name' => 'AuthTimeout',
                               'value' => 10,
                             },
                             {
                               'name' => 'ReAuthTimeout',
                               'value' => 10,
                             },
                             {
                               'name' => 'AuthGraceTime',
                               'value' => 600,
                             },
                             {
                               'name' => 'OperTimeout',
                               'value' => 1,
                             },
                             {
                               'name' => 'ReKeyTimeout',
                               'value' => 1,
                             },
                             {
                               'name' => 'TEKGraceTime',
                               'value' => 600,
                             },
                             {
                               'name' => 'AuthRejectTimeout',
                               'value' => 60,
                             },
                             {
                               'name' => 'SAMapWaitTimeout',
                               'value' => 1,
                             },
                             {
                               'name' => 'SAMapMaxRetries',
                               'value' => 4,
                             }
                           ],
          },
          {
            'name'   => 'DsServiceFlow',
            'nested' => [
                             {
                               'name' => 'DsServiceFlowRef',
                               'value' => 1,
                             },
                             {
                               'name' => 'QosParamSetType',
                               'value' => '7',
                             }
                           ],
          },
          {
            'name' => 'UsServiceFlow',
            'nested' => [
                             {
                               'name' => 'UsServiceFlowRef',
                               'value' => 2,
                             },
                             {
                               'name' => 'QosParamSetType',
                               'value' => '7',
                             },
                             {
                               'name' => 'MaxConcatenatedBurst',
                               'value' => 0,
                             }
                           ],
          },
          {
            'name' => 'MfgCVCData',
            'value' => '0xfd620bb324fb572b125078840666300d06092a8648801197310b30090603550406130255533139303706a3051197310b30090603550406130255533139303706a305203666c65205365727669636520496e7465726661636203593353051b00005040613025553311d301b060355',
          },
          {
            'name' => 'VendorSpecific',
            'value' => '0x0011ee',
            'nested' => [
                          {
                            'length' => 1,
                            'value' => '0xff',
                            'type' => 30
                          },
                          {
                            'length' => 1,
                            'value' => '0x00',
                            'type' => 31
                          },
                          {
                            'length' => 1,
                            'value' => '0x28',
                            'type' => 32
                          },
            ],
          },
          {
            'name' => 'UsPacketClass',
            'nested' => [
                          {
                            'value' => '2',
                            'name' => 'ClassifierRef'
                          },
                          {
                            'value' => 2,
                            'name' => 'ServiceFlowRef'
                          },
                          {
                            'value' => '64',
                            'name' => 'RulePriority'
                          },
                          {
                            'name' => 'IpPacketClassifier',
                            'nested' => [
                                          {
                                            'value' => 17,
                                            'name' => 'IpProto'
                                          },
                                          {
                                            'value' => 2000,
                                            'name' => 'SrcPortStart'
                                          },
                                          {
                                            'value' => 1000,
                                            'name' => 'SrcPortEnd'
                                          }
                                        ]
                          }
                        ]
          },
          {
            'name' => 'SnmpMibObject',
            'value' => {
                         'value' => 'foo-42.bin',
                         'oid' => '1.3.6.1.4.1.1429.77.1.6.1.1.6.2',
                         'type' => 'STRING'
                       },
          },
          {
            'name' => 'SnmpMibObject',
            'value' => {
                         'value' => '1.6.4.1',
                         'oid' => '1.3.6.1.4.1.1429.77.1.6.1.1.7.2',
                         'type' => 'IPADDRESS'
                       },
          },
        ];
}
