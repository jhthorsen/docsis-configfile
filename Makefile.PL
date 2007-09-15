use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'DOCSIS::Perl',
    AUTHOR              => 'Jan Henning Thorsen <pm@flodhest.net>',
    VERSION_FROM        => 'lib/DOCSIS/Perl.pm',
    ABSTRACT_FROM       => 'lib/DOCSIS/Perl.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'DOCSIS-Perl-*' },
);
