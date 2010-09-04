use inc::Module::Install;

name q(DOCSIS-ConfigFile);
all_from q(lib/DOCSIS/ConfigFile.pm);

requires q(Digest::HMAC_MD5) => 1.00;
requires q(Digest::MD5) => 2.30;
requires q(autodie) => 2.00;
requires q(bytes) => 1.00;
requires q(Math::BigInt) => 1.80;
requires q(Socket) => 1.50;

test_requires q(Test::More) => 0.90;

bugtracker q(http://rt.cpan.org/NoAuth/Bugs.html?Dist=DOCSIS-ConfigFile);
homepage q(http://search.cpan.org/dist/DOCSIS-ConfigFile);
repository q(git://github.com//home/repositories/docsis-configfile.git);

# install_script glob('bin/*');
auto_install;
WriteAll;
