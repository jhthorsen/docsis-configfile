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
                         'bytes'            => '0',
                         'Digest::MD5'      => '2.3',
                         'Digest::HMAC_MD5' => '1.0',
                         'Getopt::Euclid'   => '0.1',
                         'Math::BigInt'     => '1.7',
                         'Socket'           => '0',
                         'Test::More'       => '0',
                        #'Log::Log4perl'    => '1.0', # Strongly suggested
                        #'YAML'             => '0',   # for example script
                     },
    dist          => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean         => { FILES => 'DOCSIS-ConfigFile-*' },
);
