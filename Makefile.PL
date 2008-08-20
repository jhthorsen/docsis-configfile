use inc::Module::Install;

name     q(DOCSIS-ConfigFile);
all_from q(lib/DOCSIS/ConfigFile.pm);

requires      q(bytes)            => 0;
requires      q(Digest::MD5)      => 0;
requires      q(Digest::HMAC_MD5) => 0;
requires      q(Getopt::Euclid)   => 0;
requires      q(Math::BigInt)     => 0;
requires      q(Socket)           => 0;
test_requires q(Test::More)       => 0;
recommends    q(Log::Log4perl)    => 0;
no_index      q(directory)        => q(examples);

WriteAll;
