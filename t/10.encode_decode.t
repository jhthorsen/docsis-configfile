#!perl

use strict;
use warnings;
#use Data::Dumper;
use Test::More;
use DOCSIS::ConfigFile;

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

#print Dumper $decoded;
#print Dumper $original;

sub config { #================================================================
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
        ];
}
