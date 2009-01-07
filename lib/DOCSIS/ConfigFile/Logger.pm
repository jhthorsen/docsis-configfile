package DOCSIS::ConfigFile::Logger;

=head1 NAME

DOCSIS::ConfigFile::Logger

=head1 VERSION

See DOCSIS::ConfigFile

=head1 DESCRIPTION

This is a wrapper around C<Log::Log4perl>, but falls back to log everything,
if C<Log::Log4perl> is missing.

=cut

use strict;
use warnings;

our $LOGCONFIG     = {
    "log4perl.rootLogger"             => "ERROR, screen",
    "log4perl.appender.screen"        => "Log::Log4perl::Appender::Screen",
    "log4perl.appender.screen.layout" => "Log::Log4perl::Layout::SimpleLayout",
};
our $AUTOLOAD;


BEGIN {
    eval { require Log::Log4perl };
    warn $@ if($@);
}

=head1 METHODS

=head2 new

Returns either a C<Log::Log4perl> or C<DOCSIS::ConfigFile::Logger> object.

=cut

sub new {
    my $class = shift;

    if(%{ Log::Log4perl:: }) {
        unless(Log::Log4perl->initialized) {
            Log::Log4perl->init($LOGCONFIG);
        }
        return Log::Log4perl->get_logger($class);
    }
    else {
        return bless [], $class;
    }
}

=head2 trace

=head2 debug

=head2 info

=head2 warn

=head2 error

=head2 fatal

=cut

sub AUTOLOAD {
    my $self   = shift;
    my $msg    = shift || '';
    my($level) = $AUTOLOAD =~ /::(\w+)$/;

    return if($level eq 'DESTROY');

    warn "$level: $msg\n";

    return;
}

=head1 AUTHOR

=head1 BUGS

=head1 SUPPORT

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

See L<DOCSIS::ConfigFile>

=cut

1;
