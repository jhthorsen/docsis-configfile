#!perl

use strict;
use warnings;
use lib q(lib);
use Test::More;
use DOCSIS::ConfigFile::Encode;
use DOCSIS::ConfigFile::Decode;

use constant Encode => "DOCSIS::ConfigFile::Encode";
use constant Decode => "DOCSIS::ConfigFile::Decode";

plan tests => 2 * 10;

test_encode(bigint =>
    { value => 6000000000 },
    [ 1, 101, 160, 188, 0 ],
    6000000000,
);
test_encode(uint =>
    { value => 3000000000 },
    [ 178, 208, 94, 0 ],
    3000000000,
);
test_encode(ushort =>
    { value => 65535 },
    [ 255, 255 ],
    65535,
);
test_encode(uchar =>
    { value => 255 },
    [ 255 ],
    255,
);
test_encode(ip =>
    { value => "127.0.0.1" },
    [ 127, 0, 0, 1 ],
    "127.0.0.1"
);
test_encode(ether =>
    { value => "001122aabbcc" },
    [ 0, 17, 34, 170, 187, 204 ],
    "001122aabbcc",
);
test_encode(hexstr =>
    { value => "0x1234567890abcdef" },
    [ 18, 52, 86, 120, 144, 171, 205, 239 ],
    "0x1234567890abcdef",
);

test_encode(snmp_object =>
    {
        value => {
            oid   => "1.3.6.1.6.3",
            type  => "STRING",
            value => "hello%20world",
        }
    },
    [ 48, 20, 6, 5, 43, 6, 1, 6, 3, 4, 11, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100 ],
    {
        oid   => "1.3.6.1.6.3",
        type  => "STRING",
        value => "hello world",
    },
    "snmp_object with an uri-encoded string",
);

test_encode(snmp_object =>
    {
        value => {
            oid   => "1.3.6.1.6.3",
            type  => "STRING",
            value => "0x002244",
        }
    },
    [ 48, 12, 6, 5, 43, 6, 1, 6, 3, 4, 3, 0, 34, 68 ],
    {
        oid   => "1.3.6.1.6.3",
        type  => "STRING",
        value => "0x002244",
    },
    "snmp_object with hexstring",
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
    [  8, 3, 0, 17, 34, 2, 1, 255 ],
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
    my $function_name = shift;
    my $data = shift;
    my $is_encoded = shift;
    my $is_decoded = shift;
    my $msg = shift || $function_name;

    #use Data::Dumper;

    my $encoded = Encode->can($function_name)->($data);
    my $decoded = Decode->can($function_name)->(join "", map { chr } @$encoded);

    is_deeply($encoded, $is_encoded, "$msg -> encoded");# or diag Data::Dumper::Dumper($encoded);
    is_deeply($decoded, $is_decoded, "$msg -> decoded=value");
}

