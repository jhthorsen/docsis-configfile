#!/usr/bin/perl
use lib qw(lib);
use Test::More;
plan tests => 4;
use_ok('DOCSIS::ConfigFile');
use_ok('DOCSIS::ConfigFile::Encode');
use_ok('DOCSIS::ConfigFile::Decode');
use_ok('DOCSIS::ConfigFile::Syminfo');
