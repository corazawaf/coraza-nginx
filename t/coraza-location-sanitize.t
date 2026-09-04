#!/usr/bin/perl

# Tests for Coraza-nginx connector (Location sanitization).
#
# ngx_http_coraza_process_intervention copies intervention->data into the
# Location header on a redirect, truncating at the first control byte (any
# byte < 0x20, or 0x7f) to defend against CR/LF response splitting should
# that data ever carry client-controlled bytes.  A clean redirect target
# contains no control bytes, so it must pass through byte-for-byte unchanged.
#
# NOTE: libcoraza 1.4 does not macro-expand the redirect: target (verified: a
# %{ARGS.x} target reaches Location literally), so client-controlled request
# data cannot reach intervention->data through a normal rule today.  The
# remaining route is a literal control byte written into the redirect: target
# in the SecLang config itself.  Verified empirically (CI run 33809587491,
# "nginx mainline (full)" / "Run prove tests"): a raw 0x0d written into a
# quoted redirect: action in a rules file DOES survive SecLang parsing and
# reaches intervention->data unmodified -- the wire response was
# "Location: http://example.org/evil\r\n\r\n" with the byte after the CR
# entirely absent.  So the truncation loop below is reachable and is
# exercised for real by this file, not merely pinned as dead code.
#
# A raw LF (0x0a) is NOT exercisable through this vehicle: a rules file is
# line-oriented, so a literal LF inside the quoted redirect: target
# terminates the SecRule directive early and the rules file fails to parse
# (confirmed: with an LF case included, nginx would not start at all, taking
# down every assertion in this file, not just the LF one).  That is a
# property of the SecLang config-file grammar, not a gap in the connector --
# the truncation loop treats every byte < 0x20 identically
# (loc[safe] >= 0x20), so the CR case below already exercises the branch LF
# would take.  DEL (0x7f) is covered separately since it is outside the C0
# range and needs its own clause (loc[safe] != 0x7f).
#
# See src/ngx_http_coraza_module.c (ngx_http_coraza_process_intervention).

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(9);

# Each rules file carries a redirect: target with one literal control byte
# spliced between "evil" and "injected".  write_file() writes bytes as given
# (no interpolation), so \x0d / \x7f land on disk unmodified -- unlike a
# heredoc, where a raw control byte is fragile to carry through the tool
# chain.  (No lf.rules: see the LF note in the header comment above -- a raw
# 0x0a in a rules file terminates the directive early and the file fails to
# parse.)
$t->write_file('cr.rules',
    "SecRuleEngine On\n" .
    "SecRule ARGS:x \"\@streq go\" " .
    "\"id:30,phase:1,status:302,redirect:http://example.org/evil\x0dinjected,log,t:none\"\n");

$t->write_file('del.rules',
    "SecRuleEngine On\n" .
    "SecRule ARGS:x \"\@streq go\" " .
    "\"id:32,phase:1,status:302,redirect:http://example.org/evil\x7finjected,log,t:none\"\n");

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /redir {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule ARGS:x "@streq go" "id:20,phase:1,status:302,redirect:http://example.org/clean/path?a=b,log,t:none"
            ';
        }

        location /redir-cr {
            coraza on;
            coraza_rules_file %%TESTDIR%%/cr.rules;
        }

        location /redir-del {
            coraza on;
            coraza_rules_file %%TESTDIR%%/del.rules;
        }
    }
}
EOF

$t->run();

###############################################################################

# Clean path: no control bytes in the target, no truncation.
my $r = http_get('/redir?x=go');

like($r, qr!^HTTP/\S+ 302!, 'clean redirect returns 302');
like($r, qr!Location: http://example\.org/clean/path\?a=b\r?\n!,
    'clean Location passes through unchanged (no truncation)');

# CR: truncated at the control byte; the byte and everything after it must
# be absent, and no extra header/blank line may have been smuggled in.
my $cr = http_get('/redir-cr?x=go');

like($cr, qr!^HTTP/\S+ 302!, 'CR-target redirect still returns 302');
like($cr, qr!Location: http://example\.org/evil\r\n!,
    'CR-target Location is truncated at the control byte');
unlike($cr, qr!injected!, 'CR-target Location does not carry the byte after the CR');
is(() = ($cr =~ /^Location:/mg), 1, 'CR-target response has exactly one Location header');

# DEL (0x7f): not a C0 control byte, but explicitly in the module's cutoff set.
my $del = http_get('/redir-del?x=go');

like($del, qr!^HTTP/\S+ 302!, 'DEL-target redirect still returns 302');
like($del, qr!Location: http://example\.org/evil\r\n!,
    'DEL-target Location is truncated at the control byte');

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
