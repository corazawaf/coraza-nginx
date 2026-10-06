use strict;
use warnings;

use Test::More;
use Socket qw(AF_UNIX SOCK_STREAM PF_UNSPEC);
use FindBin;

my $source_file = "$FindBin::Bin/../t/coraza-drop-intervention.t";
open my $source, '<', $source_file or die "Cannot read $source_file: $!";
local $/ = undef;
my $text = <$source>;
close $source;
my ($helper) = $text =~ /^(sub read_response \{.*?^\})/ms;
ok(defined $helper, 'loads the integration test read helper');
die 'read helper missing' unless defined $helper;
eval $helper;
die $@ if $@;

socketpair(my $reader, my $writer, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair: $!";
close $writer;
is(read_response($reader, 1), '', 'closed socket gives the empty drop response');
close $reader;

socketpair($reader, $writer, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair: $!";
print {$writer} "HTTP/1.1 403 Forbidden\r\n\r\n";
close $writer;
is(read_response($reader, 1), "HTTP/1.1 403 Forbidden\r\n\r\n",
    'complete response is preserved');
close $reader;

socketpair($reader, $writer, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or die "socketpair: $!";
my $result = eval { read_response($reader, 1) };
my $error = $@;
is($result, undef, 'stalled socket has no successful response');
like($error, qr/^Timed out reading nginx response\n$/,
    'stalled socket read dies instead of returning an empty response');
close $reader;
close $writer;

done_testing;
