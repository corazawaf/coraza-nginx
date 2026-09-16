#!/usr/bin/perl

# (C) Andrei Belov

# Tests for Coraza-nginx connector (coraza_transaction_id).

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

# plan() counts only this file's own assertions -- Test::Nginx adds its two
# teardown checks ("no alerts" / "no sanitizer errors") to the plan itself.
# Six named checks below plus assert_no_crash()'s one makes seven.
my $t = Test::Nginx->new()->plan(7)->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    coraza_transaction_id "tid-HTTP-DEFAULT-$request_id";

    server {
        listen       127.0.0.1:8080;
        server_name  server1;

        location / {
            error_log %%TESTDIR%%/e_s1l1.log info;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq block403" "id:4,phase:1,status:403,deny,log"
            ';
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  server2;

        coraza_transaction_id "tid-SERVER-DEFAULT-$request_id";

        location / {
            error_log %%TESTDIR%%/e_s2l1.log info;
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq block403" "id:4,phase:1,status:403,deny,log"
            ';
        }

        location /specific {
            error_log %%TESTDIR%%/e_s2l2.log info;
            coraza on;
            coraza_transaction_id "tid-LOCATION-SPECIFIC-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS "@streq block403" "id:4,phase:1,status:403,deny,log"
            ';
        }

        location /debuglog {
            coraza on;
            coraza_transaction_id "tid-DEBUG-$request_id";
            coraza_rules '
                SecRuleEngine On
                SecDebugLog %%TESTDIR%%/modsec_debug.log
                SecDebugLogLevel 4
                SecRule ARGS "@streq block403" "id:4,phase:1,status:403,deny,log"
            ';
        }

    }
}
EOF

$t->run();

###############################################################################

# charge limit_req

http(<<EOF);
GET /?what=block403 HTTP/1.0
Host: server1

EOF

isnt(lines($t, 'e_s1l1.log', 'unique_id "tid-HTTP-DEFAULT-'), 0, 'http default');

http(<<EOF);
GET /?what=block403 HTTP/1.0
Host: server2

EOF

isnt(lines($t, 'e_s2l1.log', 'unique_id "tid-SERVER-DEFAULT-'), 0, 'server default');

# A second request through the same http-default location must mint a
# different transaction id -- the pattern being logged is a template
# ($request_id varies per request), not a fixed literal string reused for
# every transaction.
http(<<EOF);
GET /?what=block403 HTTP/1.0
Host: server1

EOF

my $id1 = transaction_id($t, 'e_s1l1.log', 'tid-HTTP-DEFAULT-');
my $id2 = transaction_id($t, 'e_s1l1.log', 'tid-HTTP-DEFAULT-', 2);
ok(defined $id1 && defined $id2 && $id1 ne $id2,
	'http default: two requests through the same location get distinct transaction ids');

http(<<EOF);
GET /specific/?what=block403 HTTP/1.0
Host: server2

EOF

# The location-level coraza_transaction_id must override the server-level
# default it sits under, not merely add its own log line alongside it: the
# server2 default template must NOT appear in the location's own log.
isnt(lines($t, 'e_s2l2.log', 'unique_id "tid-LOCATION-SPECIFIC-'), 0,
	'location specific: overriding template is used');
is(lines($t, 'e_s2l2.log', 'unique_id "tid-SERVER-DEFAULT-'), 0,
	'location specific: server-level template is not also logged (real override, not addition)');

http(<<EOF);
GET /debuglog/?what=block403 HTTP/1.0
Host: server2

EOF

isnt(lines($t, 'modsec_debug.log', 'tid-DEBUG-'), 0, 'libcoraza debug log');

###############################################################################

sub lines {
	my ($t, $file, $pattern) = @_;
	my $path = $t->testdir() . '/' . $file;
	open my $fh, '<', $path or return "$!";
	my $value = map { $_ =~ /\Q$pattern\E/ } (<$fh>);
	close $fh;
	return $value;
}

# Return the Nth (1-based, default 1) matched full transaction-id line's
# id-bearing suffix, so two ids from the same file can be compared for
# uniqueness across requests.
sub transaction_id {
	my ($t, $file, $prefix, $n) = @_;
	$n ||= 1;
	my $path = $t->testdir() . '/' . $file;
	open my $fh, '<', $path or return undef;
	my $seen = 0;
	while (my $line = <$fh>) {
		next unless $line =~ /unique_id "(\Q$prefix\E[^"]*)"/;
		$seen++;
		if ($seen == $n) {
			close $fh;
			return $1;
		}
	}
	close $fh;
	return undef;
}

###############################################################################

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
