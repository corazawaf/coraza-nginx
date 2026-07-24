#!/usr/bin/perl

# Tests for Coraza-nginx connector: coraza_rules declared at the http{} level are
# compiled into the main WAF (module.c: the mmcf->rules->nelts > 0 branch in
# init_process) and inherited by a location that turns coraza on without any
# rules of its own (module.c: the "lcf->rules == mmcf->rules" WAF-reuse branch).
#
# A location with coraza on and no local coraza_rules must therefore enforce the
# http-level rule set.  A second server with coraza off proves the rule only
# applies where coraza is enabled (so the inheritance is not a global side
# effect of merely declaring the rules).

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

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # Rules live at the http{} level: they build the MAIN WAF and are inherited
    # by every coraza-on location that does not override them.
    coraza_rules '
        SecRuleEngine On
        SecRule ARGS:block "@streq 1" "id:400,phase:1,deny,log,status:403"
    ';

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
        default_type text/plain;

        # coraza on, no local rules -> inherits the http-level main WAF.
        location /inherited {
            coraza on;
            return 200 "ok";
        }
    }

    # A second server with coraza OFF must not enforce the inherited rules.
    server {
        listen       127.0.0.1:%%PORT_8081%%;
        server_name  localhost;
        default_type text/plain;

        location /off {
            coraza off;
            return 200 "ok";
        }
    }
}
EOF

$t->run();
$t->todo_alerts();
$t->plan(3);

###############################################################################

# The http-level rule fires in a location that only turns coraza on.
like(http_get('/inherited?block=1'), qr/^HTTP.*403/,
    'http-level coraza_rules inherited and enforced in a coraza-on location');

# Positive control: a request that does not match passes through.
like(http_get('/inherited?block=0'), qr/^HTTP.*200/,
    'non-matching request passes the inherited rule set');

# Negative control: coraza off ignores the inherited rules entirely.
like(http_get('/off?block=1', PeerAddr => '127.0.0.1:' . port(8081)),
    qr/^HTTP.*200/,
    'coraza off does not enforce inherited http-level rules (control)');
