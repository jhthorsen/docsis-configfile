use strict;
use warnings;
use Test::More;
use DOCSIS::ConfigFile qw( decode_docsis encode_docsis );

my ($bytes, $output);

=cut
<VendorSpecific 0x0011ee>
# type value (length is calculated)
  30 0xff
  31 0x00
  32 0x28
</VendorSpecific>
<SnmpMibObject 1.3.6.1.4.1.1429.77.1.6.1.1.6.2>
  STRING bootfile.bin
</SnmpMibObject>
=cut

my $input = {
  GlobalPrivacyEnable => 1,
  MaxCPE              => 2,
  NetworkAccess       => 1,
  BaselinePrivacy     => {
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
  UsServiceFlow => {UsServiceFlowRef => 2, QosParamSetType => 7, MaxConcatenatedBurst => 0},
  UsPacketClass => {
    ClassifierRef      => 2,
    ServiceFlowRef     => 2,
    RulePriority       => 64,
    IpPacketClassifier => {IpProto => 17, SrcPortStart => 1000, SrcPortEnd => 2000}
  }
};

$bytes = encode_docsis($input);
is length $bytes, 104, 'encode_docsis';

$output = decode_docsis($bytes);
delete $input->{foo};
is_deeply $output, $input, 'decode_docsis';

done_testing;
