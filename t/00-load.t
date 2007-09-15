#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'DOCSIS::Perl' );
}

diag( "Testing DOCSIS::Perl $DOCSIS::Perl::VERSION, Perl $], $^X" );
