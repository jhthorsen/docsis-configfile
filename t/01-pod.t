#!perl -T

use Test::More;

if(eval 'require Test::Pod 1.14') {
    all_pod_files_ok();
}
else {
    plan skip_all => 'Test::Pod 1.14 required for testing POD';
}

