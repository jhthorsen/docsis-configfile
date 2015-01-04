use warnings;
use strict;
use Test::More;
use DOCSIS::ConfigFile;

plan skip_all => 'cannot find test-files' unless -e 't/data/rt70882/encoded.cm.zero';

my $zero_file     = 't/data/rt70882/encoded.cm.zero';
my $non_zero_file = 't/data/rt70882/encoded.cm.non_zero';
my $docsis        = DOCSIS::ConfigFile->new;
my $zero          = $docsis->decode($zero_file);
my $non_zero      = $docsis->decode($non_zero_file);
my $zero_bin;

$_->{name} =~ /Mic/ and $_->{value} = 'MIC' for @$zero;
$_->{name} =~ /Mic/ and $_->{value} = 'MIC' for @$non_zero;
is_deeply $zero, $non_zero, 'decoded without trailing zero';

$zero_bin = $docsis->encode($zero);
like $zero_bin, qr{DataS_U_512k\0}, 'encoded with trailing zero';

done_testing;
