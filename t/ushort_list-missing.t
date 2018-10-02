use strict;
use warnings;
use Test::More;
use DOCSIS::ConfigFile qw(decode_docsis encode_docsis);

plan skip_all => 'cannot find tos.bin' unless -e 't/data/ushort_list-missing.bin';

my $decoded = eval { decode_docsis \'t/data/ushort_list-missing.bin' };
ok !$@, 'ushort_list() is present in DOCSIS::ConfigFile::Decode' or diag $@;

use Data::Dumper;
warn Data::Dumper::Dumper($decoded);

done_testing;
