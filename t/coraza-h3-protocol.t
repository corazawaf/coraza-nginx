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
# NOTE: HTTP/3 needs nginx >= 1.25.0 built with --with-http_v3_module. CI
# currently builds 1.24.0, so this test skips there and the mapping is
# covered by coraza-h3-protocol-map.t, which runs everywhere. This test
# starts running as soon as CI moves to an HTTP/3-capable nginx.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3 cryptx/)
	->has_daemon('openssl')->plan(3);

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

        # Negative control: denies when the WAF sees HTTP/1.0. Before the fix
        # this fired on an HTTP/3 request, which is the bug itself.
        location /h1 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecRule REQUEST_PROTOCOL "@streq HTTP/1.0" "id:10,phase:1,status:401,deny,log"
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
$t->write_file('none', 'body');

$t->run();

###############################################################################

is(get_status('/h3'), 403,
	'HTTP/3 request is reported to the WAF as HTTP/3.0');
is(get_status('/h1'), 200,
	'HTTP/3 request is not reported to the WAF as HTTP/1.0');
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
