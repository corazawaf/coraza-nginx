#!/usr/bin/perl

# Tests for Coraza-nginx connector: the log-phase handler must tolerate a request
# that reached the LOG phase without a Coraza context ever being created
# (ngx_http_coraza_log.c: the ctx == NULL guard).  This happens when nginx
# rejects a request before FIND_CONFIG (400/414/494): PREACCESS never runs,
# and the header filter and the LOG handler both see the server-level
# configuration, since no location was ever matched.  With `coraza on` only
# inside a location, that configuration has Coraza disabled, so neither site
# binds a transaction and the LOG handler must return without dereferencing
# a NULL context.
#
# (With `coraza on` at server level the header filter would bind a transaction
# for the rejected request instead, and this guard would never be reached.)

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use lib '.';
use coraza_crash_check;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;
        default_type text/plain;

        # Coraza stays off at server level on purpose: a request rejected
        # before FIND_CONFIG is handled with this configuration, so nothing
        # creates a context for it.  The audit log is inherited by location /
        # and records every transaction that does get bound.
        coraza_rules '
            SecRuleEngine On
            SecAuditEngine On
            SecAuditLogParts ABFHZ
            SecAuditLogFormat JSON
            SecAuditLogType Serial
            SecAuditLog %%TESTDIR%%/audit.log
        ';

        # Small header buffers so an oversized request line is rejected with a
        # client error BEFORE FIND_CONFIG runs -> no Coraza context.
        large_client_header_buffers 2 512;

        location / {
            coraza on;
            return 200 "ok";
        }
    }
}
EOF

$t->run();
$t->plan(5);

###############################################################################

my $audit = $t->testdir() . '/audit.log';

# An oversized request line is rejected (414) before FIND_CONFIG, so the log
# handler runs with ctx == NULL and the server-level configuration declines
# to create one.  A clean worker (no crash on the next request) proves the
# NULL-context path was handled gracefully.
my $big = '/' . ('a' x 2048);
like(http_get($big), qr/^HTTP\S+ 414/,
    'oversized request line rejected before FIND_CONFIG (no Coraza context at log)');

select undef, undef, undef, 0.3;
is(entries(), 0, 'rejected request bound no transaction: audit log is empty');

# The worker survived the NULL-context log path and still serves normally.
like(http_get('/'), qr/^HTTP\S+ 200/,
    'worker healthy after logging a context-less request');

# Positive control: the enabled location does bind and audit a transaction,
# so an empty audit log above means "no transaction", not "no audit log".
for (1 .. 50) {
    last if entries() > 0;
    select undef, undef, undef, 0.1;
}
is(entries(), 1, 'enabled location audited its request once');

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');

###############################################################################

sub entries {
	return 0 unless -e $audit;
	open my $fh, '<', $audit or die "open $audit: $!";
	my $n = grep { /"transaction"/ } <$fh>;
	close $fh;
	return $n;
}
