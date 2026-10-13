#!/usr/bin/perl

# Static regression check for connection information extraction.
#
# coraza_process_connection() returns CORAZA_OK (0) on success, so the
# failure branch after the call must test ret != 0. Testing ret != 1 treated
# every successful lookup as a failure, and CORAZA_DDEBUG builds logged
# "Was not able to extract connection information" on ordinary requests.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";
my $src = slurp("$root/src/ngx_http_coraza_rewrite.c");

like($src,
	qr/ret\s*=\s*coraza_process_connection\(.*?\);\s*if\s*\(ret\s*!=\s*0\)/s,
	'connection lookup treats 0 (CORAZA_OK) as success');

unlike($src,
	qr/ret\s*=\s*coraza_process_connection\(.*?\);\s*if\s*\(ret\s*!=\s*1\)/s,
	'connection lookup does not treat 1 as success');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
