#!perl -T

use Test::More tests => 1;
use lib q(lib);

BEGIN {
	use_ok( 'DOCSIS::ConfigFile' );
}

diag( "Testing DOCSIS::ConfigFile $DOCSIS::ConfigFile::VERSION, Perl $], $^X" );
