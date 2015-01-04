BEGIN { $ENV{DOCSIS_CAN_TRANSLATE_OID} = 0; }
use warnings;
use strict;
use lib qw(lib);
use Test::More;
use DOCSIS::ConfigFile;

my $docsis = DOCSIS::ConfigFile->new;

eval {
  $docsis->encode([{name => 'DownstreamFrequency', value => 88000000,}]);
  ok 1, 'encoded DownstreamFrequency';
} or do {
  ok 0, 'could not encode DownstreamFrequency';
  diag $@;
};

done_testing;
