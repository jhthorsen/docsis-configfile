use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME          => 'DOCSIS::ConfigFile',
    AUTHOR        => 'Jan Henning Thorsen <pm@flodhest.net>',
    VERSION_FROM  => 'lib/DOCSIS/ConfigFile.pm',
    ABSTRACT_FROM => 'lib/DOCSIS/ConfigFile.pm',
    PL_FILES      => {},
    PREREQ_PM     => {
                         'bytes'            => 0,
                         'Digest::MD5'      => 0,
                         'Digest::HMAC_MD5' => 0,
                         'Math::BigInt'     => 0,
                         'Socket'           => 0,
                         'Test::More'       => 0,
                     },
    dist          => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean         => { FILES => 'DOCSIS-ConfigFile-*' },
);
