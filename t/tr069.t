use strict;
use warnings;
use Test::More;
use DOCSIS::ConfigFile qw( decode_docsis encode_docsis );

my $input = 
{ 'name' => 'eRouter',
  'nested' => [
    { 'name' => 'ManagementServer',
      'nested' => [
        { 'value' => 1,
          'name' => 'EnableCWMP'},
        { 'value' => 'http://tr069.example.com/',
          'name' => 'URL'},
        { 'value' => 'goodUser',
          'name' => 'Username'},
        { 'value' => 'passwordsAreGood',
          'name' => 'Password'},
        { 'value' => 'remoteUser',
          'name' => 'ConnectionRequestUsername'},
        { 'value' => 'securePasswordsAreBetter',
          'name' => 'ConnectionRequestPassword'},
        { 'value' => 1,
          'name' => 'ACSOverride'},
      ]
    }
  ]
};

my ($bytes, $output);

{
  $bytes = encode_docsis($input);
  is length $bytes, 48, 'encode_docsis';

  $output = decode_docsis($bytes);
  delete $output->{$_} for qw( CmtsMic CmMic GenericTLV );
  is_deeply $output, $input, 'decode_docsis';
}

done_testing;
