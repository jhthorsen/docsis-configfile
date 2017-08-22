use strict;
use warnings;
use Test::More;
use DOCSIS::ConfigFile qw( decode_docsis encode_docsis );

my $input = {
    eRouter  => {
                  InitializationMode => 3,

                  ManagementServer  => {    EnableCWMP => 1,
                                            URL => "Http://www.acs.de:7547",
                                            Username => "testuser",
                                            Password => "testpass",
                                            ConnectionRequestUsername => "connuser",
                                            ConnectionRequestPassword => "connpass",
                                            ACSOverride => 0 },

                  InitializationModeOverride => 1,
                }
};

my ($bytes, $output);

{
  $bytes = encode_docsis($input);

  is length $bytes, 120, 'encode_docsis';

  $output = decode_docsis($bytes);
  delete $output->{$_} for qw( CmtsMic CmMic GenericTLV );
  is_deeply $output, $input, 'decode_docsis';
}

done_testing;
