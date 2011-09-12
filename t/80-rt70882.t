use warnings;
use strict;
use lib qw(lib);
use Test::More;
use DOCSIS::ConfigFile;

plan skip_all => 'cannot find test-files' unless(-e 't/data/rt70882/encoded.cm.zero');
plan tests => 2;

{
    my $zero_file = 't/data/rt70882/encoded.cm.zero';
    my $non_zero_file = 't/data/rt70882/encoded.cm.non_zero';
    my $docsis = DOCSIS::ConfigFile->new;

    my $zero_hash = $docsis->decode($zero_file);
    my $non_zero_hash  = $docsis->decode($non_zero_file);

    $_->{'name'} =~ /Mic/ and $_->{'value'} = 'MIC' for @$zero_hash;
    $_->{'name'} =~ /Mic/ and $_->{'value'} = 'MIC' for @$non_zero_hash;

    is_deeply($zero_hash, $non_zero_hash, 'decoded without trailing zero');

    my $zero_bin = $docsis->encode($zero_hash);
    like($zero_bin, qr{DataS_U_512k\0}, 'encoded with trailing zero');

    #use Data::Dumper; print Dumper($zero); print Dumper($non_zero);
}
