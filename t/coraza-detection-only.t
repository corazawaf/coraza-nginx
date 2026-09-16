#!/usr/bin/perl

# Tests for Coraza-nginx connector (SecRuleEngine DetectionOnly).
#
# SecRuleEngine DetectionOnly is documented Coraza/CRS behaviour -- rules run
# and log but never intervene -- yet nothing in this suite pins that the
# connector actually honours it: that a rule which would deny under
# SecRuleEngine On instead only logs and lets the request through under
# DetectionOnly.
#
# Two locations carry the same phase-1 deny rule (same variable, operator,
# disruptive action and status; ids differ only because Coraza requires them
# to be unique) and differ in SecRuleEngine. The DetectionOnly location adds
# `auditlog` plus a SecAuditLog file: that changes only what gets recorded,
# never whether the rule intervenes. Asserting the DetectionOnly location
# returns 200 alone would be consistent with the rule silently never running
# at all, so this also checks that audit log for the rule's msg to prove it
# matched. A benign request to each location is the negative control,
# proving the 403/200 split above is the rule engine mode and not some other
# difference between the two locations.
# See src/ngx_http_coraza_module.c (phase evaluation / intervention handling).
#
# ROOT CAUSE (VERIFIED, static read + CI, 2026-09-03): a match under
# DetectionOnly is NOT observable via nginx's error.log through this
# connector. coraza_process_logging() (src/ngx_http_coraza_dl.c) is a bare
# `int (*)(coraza_transaction_t)` call into libcoraza with no callback
# parameter of any kind -- grep every fn_coraza_* typedef in
# ngx_http_coraza_dl.c and none of them is a logging callback. Nothing in
# ngx_http_coraza_log.c or ngx_http_coraza_module.c wraps that call with
# ngx_log_error(); libcoraza's audit engine writes wherever SecAuditLog (or
# SecDebugLog) points it, entirely independent of the nginx log. This is why
# grepping error.log for the msg (CI, 2026-09-03) found nothing: it was
# asking the wrong oracle, not evidence that DetectionOnly fails to log.
# t/coraza-config-auditlog.t already proves the right oracle -- SecAuditLog
# <file> plus SecAuditLogParts -- picks up matched-rule content end-to-end
# for this connector, so this file uses the same idiom below.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(6);

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

        location /on {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq bad" "id:50,phase:1,deny,status:403,log,msg:\'detectiononly-probe\',t:none"
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }

        location /detect {
            coraza on;
            coraza_rules '
                SecRuleEngine DetectionOnly
                SecRule ARGS:x "@streq bad" "id:51,phase:1,deny,status:403,log,auditlog,msg:\'detectiononly-probe\',t:none"
                SecAuditEngine On
                SecAuditLogParts ABKZ
                SecAuditLog %%TESTDIR%%/auditlog-detect.txt
                SecAuditLogType Serial
            ';
            return 200 "TEST-OK-IF-YOU-SEE-THIS";
        }
    }
}
EOF

$t->run();

###############################################################################

# SecRuleEngine On: the rule blocks as usual.
my $blocked = http_get('/on?x=bad');
like($blocked, qr!^HTTP/\S+ 403!, 'SecRuleEngine On blocks the matching request');

# SecRuleEngine DetectionOnly: the same rule matches but must not block.
my $detected = http_get('/detect?x=bad');
like($detected, qr!^HTTP/\S+ 200!, 'SecRuleEngine DetectionOnly does not block a matching request');

# Benign requests to each location pass regardless of engine mode.
like(http_get('/on?x=fine'), qr!^HTTP/\S+ 200!, 'benign request passes under SecRuleEngine On');
like(http_get('/detect?x=fine'), qr!^HTTP/\S+ 200!, 'benign request passes under SecRuleEngine DetectionOnly');

$t->stop();

# Proves the DetectionOnly rule actually matched rather than silently not
# running at all -- without this the 200 above is consistent with either.
# error.log is not the oracle for this (see the ROOT CAUSE note above); the
# SecAuditLog file the /detect location was configured with is.
my $d = $t->testdir();
my $detect_audit = do {
	local $/ = undef;
	open my $fh, "<", "$d/auditlog-detect.txt"
		or die "could not open: $!";
	<$fh>;
};
like($detect_audit, qr/detectiononly-probe/,
	'SecRuleEngine DetectionOnly rule logged a match via SecAuditLog for the tripping request');

unlike($t->read_file('error.log'), qr/signal 11|SIGSEGV|AddressSanitizer/,
	'no crash handling SecRuleEngine DetectionOnly');

###############################################################################
