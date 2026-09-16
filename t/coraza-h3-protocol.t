#!/usr/bin/perl

# Tests for the protocol version reported to the WAF over HTTP/3.
#
# The rewrite handler maps r->http_version to the protocol string passed to
# coraza_process_uri(). With no case for HTTP/3 the mapping fell through to
# the "1.0" default, so REQUEST_PROTOCOL read HTTP/1.0 on a QUIC request and
# any rule keyed on it silently failed to match.
#
# Each location below denies on a specific REQUEST_PROTOCOL value, so the
# status code tells us exactly which string the WAF saw.
#
# NOTE: HTTP/3 needs nginx >= 1.25.0 built with --with-http_v3_module. The
# CI cell that runs prove builds nginx mainline with that flag, so this test
# runs for real there; it skips on any server built without HTTP/3, where
# the mapping is still covered by coraza-h3-protocol-map.t.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

use lib '.';
use coraza_crash_check;
use Test::Nginx::HTTP3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3 cryptx/)
	->has_daemon('openssl')->plan(5);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name  localhost;

        # Denies only when the WAF sees HTTP/3.0. Before the fix this never
        # fired, because HTTP/3 was reported as HTTP/1.0.
        location /h3 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_PROTOCOL "@streq HTTP/3.0" "id:30,phase:1,status:403,deny,log"
            ';
        }

        # Negative control: denies when the WAF sees HTTP/1.0, the value the
        # switch's default arm produces. Restoring the missing HTTP/3 case
        # makes an HTTP/3 request fall through to that default and 401 here,
        # so this location fails if the mapping regresses. (It only proves
        # that once the mapping emits the slash-delimited form -- against a
        # bare "1.0" the @streq cannot match and this passes vacuously.)
        location /h1 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_PROTOCOL "@streq HTTP/1.0" "id:10,phase:1,status:401,deny,log"
            ';
        }

        # Response side: the header filter reports the response protocol to
        # the WAF from r->http_version.  Before the fix it keyed on r->stream
        # (HTTP/2 only), so an HTTP/3 response was reported as HTTP/1.1 and a
        # RESPONSE_PROTOCOL rule never matched HTTP/3.0.  RESPONSE_PROTOCOL is
        # a phase-3 (response-headers) variable and the connector applies
        # response intervention in the header filter, so deny on HTTP/3.0 at
        # phase:3 proves the response-side mapping.
        location /resp {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_PROTOCOL "@streq HTTP/3.0" "id:35,phase:3,status:403,deny,log"
            ';
        }

        # Sanity: coraza is active here but no protocol rule matches.
        location /none {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_PROTOCOL "@streq HTTP/9.9" "id:99,phase:1,status:402,deny,log"
            ';
        }
    }
}
EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('h3', 'body');
$t->write_file('h1', 'body');
$t->write_file('resp', 'body');
$t->write_file('none', 'body');

$t->run();

###############################################################################

is(get_status('/h3'), 403,
	'HTTP/3 request is reported to the WAF as HTTP/3.0');
is(get_status('/h1'), 200,
	'HTTP/3 request is not reported to the WAF as HTTP/1.0');
is(get_status('/resp'), 403,
	'HTTP/3 response is reported to the WAF as HTTP/3.0 (phase 3)');
is(get_status('/none'), 200,
	'no protocol rule matches, request is served');

###############################################################################

sub get_status {
	my ($path) = @_;

	my $s = Test::Nginx::HTTP3->new();
	my $sid = $s->new_stream({ path => $path });
	my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);

	my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
	return undef unless defined $frame;
	return $frame->{headers}->{':status'};
}

coraza_crash_check::assert_no_crash($t,
	'no worker crash in error.log');
