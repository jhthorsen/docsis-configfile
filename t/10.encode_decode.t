#!perl

use strict;
use warnings;
#use Data::Dumper;
use Test::More;
use DOCSIS::ConfigFile;

my $original = config();
my $obj      = DOCSIS::ConfigFile->new;
my $encoded  = $obj->encode(config    => $original);
my $decoded  = $obj->decode(binstring => $encoded);
my $i        = 0;

plan tests => scalar(@$original);

for my $o (@$original) {
    is($decoded->[$i]->{'name'}, $o->{'name'}, "$o->{'name'} is ok");
    $i++;
}

#print Dumper $decoded;
#print Dumper $original;

sub config { #================================================================
    return [
          {
            'length' => 1,
            'ulimit' => 1,
            'llimit' => 0,
            'value' => '1',
            'name' => 'NetworkAccess',
            'func' => 'uchar',
            'pcode' => 0,
            'code' => 3
          },
          {
            'length' => 1,
            'ulimit' => 0,
            'llimit' => 0,
            'value' => '1',
            'name' => 'GlobalPrivacyEnable',
            'func' => 'uchar',
            'pcode' => 0,
            'code' => 29
          },
          {
            'length' => 1,
            'ulimit' => 254,
            'llimit' => 1,
            'value' => '1',
            'name' => 'MaxCPE',
            'func' => 'uchar',
            'pcode' => 0,
            'code' => 18
          },
          {
            'llimit' => 0,
            'name' => 'BaselinePrivacy',
            'pcode' => 0,
            'length' => 54,
            'ulimit' => 0,
            'func' => 'aggregate',
            'aggregate' => [
                             {
                               'length' => 4,
                               'ulimit' => 30,
                               'llimit' => 1,
                               'value' => 10,
                               'name' => 'AuthTimeout',
                               'func' => 'uint',
                               'pcode' => 17,
                               'code' => 1
                             },
                             {
                               'length' => 4,
                               'ulimit' => 30,
                               'llimit' => 1,
                               'value' => 10,
                               'name' => 'ReAuthTimeout',
                               'func' => 'uint',
                               'pcode' => 17,
                               'code' => 2
                             },
                             {
                               'length' => 4,
                               'ulimit' => 6047999,
                               'llimit' => 1,
                               'value' => 600,
                               'name' => 'AuthGraceTime',
                               'func' => 'uint',
                               'pcode' => 17,
                               'code' => 3
                             },
                             {
                               'length' => 4,
                               'ulimit' => 10,
                               'llimit' => 1,
                               'value' => 1,
                               'name' => 'OperTimeout',
                               'func' => 'uint',
                               'pcode' => 17,
                               'code' => 4
                             },
                             {
                               'length' => 4,
                               'ulimit' => 10,
                               'llimit' => 1,
                               'value' => 1,
                               'name' => 'ReKeyTimeout',
                               'func' => 'uint',
                               'pcode' => 17,
                               'code' => 5
                             },
                             {
                               'length' => 4,
                               'ulimit' => 302399,
                               'llimit' => 1,
                               'value' => 600,
                               'name' => 'TEKGraceTime',
                               'func' => 'uint',
                               'pcode' => 17,
                               'code' => 6
                             },
                             {
                               'length' => 4,
                               'ulimit' => 600,
                               'llimit' => 1,
                               'value' => 60,
                               'name' => 'AuthRejectTimeout',
                               'func' => 'uint',
                               'pcode' => 17,
                               'code' => 7
                             },
                             {
                               'length' => 4,
                               'ulimit' => 10,
                               'llimit' => 1,
                               'value' => 1,
                               'name' => 'SAMapWaitTimeout',
                               'func' => 'uint',
                               'pcode' => 17,
                               'code' => 8
                             },
                             {
                               'length' => 4,
                               'ulimit' => 10,
                               'llimit' => 0,
                               'value' => 4,
                               'name' => 'SAMapMaxRetries',
                               'func' => 'uint',
                               'pcode' => 17,
                               'code' => 9
                             }
                           ],
            'code' => 17
          },
          {
            'llimit' => 0,
            'name' => 'DsServiceFlow',
            'pcode' => 0,
            'length' => 7,
            'ulimit' => 0,
            'func' => 'aggregate',
            'aggregate' => [
                             {
                               'length' => 2,
                               'ulimit' => 65535,
                               'llimit' => 1,
                               'value' => 1,
                               'name' => 'DsServiceFlowRef',
                               'func' => 'ushort',
                               'pcode' => 25,
                               'code' => 1
                             },
                             {
                               'length' => 1,
                               'ulimit' => 255,
                               'llimit' => 0,
                               'value' => '7',
                               'name' => 'QosParamSetType',
                               'func' => 'uchar',
                               'pcode' => 25,
                               'code' => 6
                             }
                           ],
            'code' => 25
          },
          {
            'llimit' => 0,
            'name' => 'UsServiceFlow',
            'pcode' => 0,
            'length' => 11,
            'ulimit' => 0,
            'func' => 'aggregate',
            'aggregate' => [
                             {
                               'length' => 2,
                               'ulimit' => 65535,
                               'llimit' => 1,
                               'value' => 2,
                               'name' => 'UsServiceFlowRef',
                               'func' => 'ushort',
                               'pcode' => 24,
                               'code' => 1
                             },
                             {
                               'length' => 1,
                               'ulimit' => 255,
                               'llimit' => 0,
                               'value' => '7',
                               'name' => 'QosParamSetType',
                               'func' => 'uchar',
                               'pcode' => 24,
                               'code' => 6
                             },
                             {
                               'length' => 2,
                               'ulimit' => 65535,
                               'llimit' => 0,
                               'value' => 0,
                               'name' => 'MaxConcatenatedBurst',
                               'func' => 'ushort',
                               'pcode' => 24,
                               'code' => 14
                             }
                           ],
            'code' => 24
          },
        ];
}
