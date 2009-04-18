#!perl

use strict;
use warnings;
use Test::More;
use DOCSIS::ConfigFile::Encode;
use DOCSIS::ConfigFile::Decode;
use constant Encode => "DOCSIS::ConfigFile::Encode";
use constant Decode => "DOCSIS::ConfigFile::Decode";

plan tests => 2 * 10;

test_encode(bigint =>
    { value => 6000000000 }, 6000000000
);
test_encode(uint =>
    { value => 3000000000 }, 3000000000
);
test_encode(ushort =>
    { value => 65535 }, 65535
);
test_encode(uchar =>
    { value => 255 }, 255
);
test_encode(ip =>
    { value => "127.0.0.1" }, "127.0.0.1"
);
test_encode(ether =>
    { value => "001122aabbcc" }, "001122aabbcc"
);
test_encode(hexstr =>
    { value => "0x1234567890abcdef" }, "0x1234567890abcdef"
);

test_encode(snmp_object =>
    {
        value => {
            oid   => "1.3.6.1.6.3",
            type  => "STRING",
            value => "hello%20world",
        }
    },
    {
        oid   => "1.3.6.1.6.3",
        type  => "STRING",
        value => "hello world",
    },
    "snmp_object with an uri-encoded string"
);

test_encode(snmp_object =>
    {
        value => {
            oid   => "1.3.6.1.6.3",
            type  => "STRING",
            value => "0x002244",
        }
    },
    {
        oid   => "1.3.6.1.6.3",
        type  => "STRING",
        value => "0x002244",
    },
    "snmp_object with hexstring"
);

test_encode(vendorspec => 
    {
        value => "0x001122",
        nested => [
            {
                type => 0x02,
                length => 0x04,
                value => "0xff",
            },
        ],
    },
    [
        {
            type => 0x02,
            length => 0x1,
            value => "0xff",
        }
    ]
);

=head1 FUNCTIONS

=head2 test_encode

=cut

sub test_encode {
    my $sub      = shift;
    my $data     = shift;
    my $expected = shift;
    my $msg      = shift || $sub;

    my @encoded = Encode->can($sub)->($data);
    my $decoded = Decode->can($sub)->(join "", map { chr } @encoded);

    ok(scalar(@encoded), "$msg -> encoded");
    is_deeply($decoded, $expected, "$msg -> decoded=value");
}

