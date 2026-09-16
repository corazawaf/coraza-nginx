#!/usr/bin/perl

# (C) Thijs Eilander

# Tests for Coraza-nginx connector: WAFs are deduplicated by rule *content*,
# not by rules-array pointer identity.
#
# Two server blocks that spell out byte-identical coraza_rules directives get
# distinct ngx_array_t rules arrays from the config parser, so the old
# pointer-identity check never matched them and the connector compiled the
# ruleset once per block.  Content comparison collapses those into one WAF.
#
# The negative control is the load-bearing half: blocks with *different* rules
# must keep separate WAFs, so a rule declared in one block must not fire in
# the other.  An over-eager dedup would silently merge distinct policies, and
# nothing else in the suite would notice.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(12);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

error_log %%TESTDIR%%/error.log notice;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    coraza on;

    # --- Two blocks with byte-identical rules: must share one WAF. ---

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  dedup_a;

        coraza_rules '
            SecRuleEngine On
            SecRule REQUEST_URI "@contains /shared-attack" "id:1001,phase:1,deny,log,status:403,t:none"
        ';

        location / {
            return 200 "OK-A\n";
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8081%%;
        server_name  dedup_b;

        coraza_rules '
            SecRuleEngine On
            SecRule REQUEST_URI "@contains /shared-attack" "id:1001,phase:1,deny,log,status:403,t:none"
        ';

        location / {
            return 200 "OK-B\n";
        }
    }

    # --- Negative control: different rules, must NOT share. ---
    #
    # Block C denies /only-in-c.  Block D denies /only-in-d.  If dedup merged
    # them, one block's rule would start firing in the other.

    server {
        listen       127.0.0.1:%%PORT_8082%%;
        server_name  distinct_c;

        coraza_rules '
            SecRuleEngine On
            SecRule REQUEST_URI "@contains /only-in-c" "id:2001,phase:1,deny,log,status:403,t:none"
        ';

        location / {
            return 200 "OK-C\n";
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8083%%;
        server_name  distinct_d;

        coraza_rules '
            SecRuleEngine On
            SecRule REQUEST_URI "@contains /only-in-d" "id:2002,phase:1,deny,log,status:403,t:none"
        ';

        location / {
            return 200 "OK-D\n";
        }
    }

    # --- Order control: same two rules, opposite order. ---
    #
    # In E, the SecAction sets tx.order_probe before the SecRule reads it, so
    # /order-probe is denied.  In F, the SecRule runs before the variable is
    # set and the request passes.  A comparison that ignores order would merge
    # the two WAFs and make one server use the other's policy.

    server {
        listen       127.0.0.1:%%PORT_8084%%;
        server_name  order_e;

        coraza_rules 'SecRuleEngine On';
        coraza_rules 'SecAction "id:3001,phase:1,pass,nolog,setvar:tx.order_probe=1"';
        coraza_rules 'SecRule TX:order_probe "@eq 1" "id:3002,phase:1,deny,nolog,status:403,t:none"';

        location / {
            return 200 "OK-E\n";
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8085%%;
        server_name  order_f;

        coraza_rules 'SecRuleEngine On';
        coraza_rules 'SecRule TX:order_probe "@eq 1" "id:3002,phase:1,deny,nolog,status:403,t:none"';
        coraza_rules 'SecAction "id:3001,phase:1,pass,nolog,setvar:tx.order_probe=1"';

        location / {
            return 200 "OK-F\n";
        }
    }
}

EOF

$t->run();

###############################################################################

# --- Sharing: identical blocks both enforce. ---

like(http_get('/shared-attack', socket => port_socket(8080)), qr/ 403 /,
	'identical block A blocks the hostile request');
like(http_get('/shared-attack', socket => port_socket(8081)), qr/ 403 /,
	'identical block B blocks the hostile request');
like(http_get('/benign', socket => port_socket(8080)), qr/OK-A/,
	'identical block A passes a benign request');
like(http_get('/benign', socket => port_socket(8081)), qr/OK-B/,
	'identical block B passes a benign request');

# --- NEGATIVE CONTROL: distinct blocks did not merge. ---

like(http_get('/only-in-c', socket => port_socket(8082)), qr/ 403 /,
	'control: block C enforces its own rule');
like(http_get('/only-in-c', socket => port_socket(8083)), qr/OK-D/,
	'control: block C rule does NOT fire in block D');
like(http_get('/only-in-d', socket => port_socket(8083)), qr/ 403 /,
	'control: block D enforces its own rule');
like(http_get('/only-in-d', socket => port_socket(8082)), qr/OK-C/,
	'control: block D rule does NOT fire in block C');

# --- ORDER CONTROL: the same two rules have different sequential effects. ---

like(http_get('/order-probe', socket => port_socket(8084)), qr/ 403 /,
	'order E sets the transaction variable before the deny rule reads it');
like(http_get('/order-probe', socket => port_socket(8085)), qr/OK-F/,
	'order F evaluates the deny rule before the variable is set');

# --- The sharing itself, observed in the worker's startup log. ---
#
# ngx_http_coraza_init_process() logs one "loc WAF initialized" line per WAF
# it actually builds, and one "main WAF initialized" line per worker.
#
# Twelve rule-bearing loc_confs reach init_process: one per server plus one per
# location, because each location inherits its server's rules pointer.  The six
# inherited locations already share through pointer identity, so the observed
# pre-change count was six distinct WAFs per worker.  A and B have identical
# content in distinct arrays, so content comparison reduces that count to five.
#
# Normalise by the worker count: the harness may start more than one worker,
# and init_process runs once in each.

my $log = $t->read_file('error.log');
my $workers = () = $log =~ /main WAF initialized/g;
my $built   = () = $log =~ /loc WAF initialized/g;

cmp_ok($workers, '>', 0, 'at least one worker reported WAF initialization');

is($built, 5 * $workers,
	"per worker: 6 distinct rules arrays produced "
	. ($workers ? $built / $workers : $built)
	. " WAFs (5 expected: A and B share one)");

###############################################################################

sub port_socket {
	my ($port) = @_;
	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1',
		PeerPort => port($port),
	) or die "Can't connect to nginx: $!\n";

	return $s;
}

###############################################################################
