#!perl -T

use lib q(lib);
eval 'use Test::Pod::Coverage 1.04';

if($@) {
    plan(skip_all =>
        'Test::Pod::Coverage 1.04 required for testing POD coverage'
    ) if $@;
}

all_pod_coverage_ok();
