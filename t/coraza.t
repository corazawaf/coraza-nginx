#!/usr/bin/perl

#
# Coraza, http://www.coraza.io/
# Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
#
# You may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# If any of the files related to licensing are missing or if you have any
# other questions related to licensing please contact Trustwave Holdings, Inc.
# directly using the email address security@coraza.io.
#


# Tests for Coraza module.

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

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /phase1 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecDefaultAction "phase:1,log,auditlog,pass"
                SecDefaultAction "phase:2,log,auditlog,pass"
                SecRule ARGS "@streq redirect301" "id:1,phase:1,status:301,log,redirect:http://www.coraza.io"
                SecRule ARGS "@streq redirect302" "id:2,phase:1,status:302,log,redirect:http://www.coraza.io"
                SecRule ARGS "@streq block401" "id:3,phase:1,status:401,deny,log"
                SecRule ARGS "@streq block403" "id:4,phase:1,status:403,deny,log"
            ';
        }
        location /phase2 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecDefaultAction "phase:1,log,auditlog,pass"
                SecDefaultAction "phase:2,log,auditlog,pass"
                SecRule ARGS "@streq redirect301" "id:1,phase:2,status:301,log,redirect:http://www.coraza.io"
                SecRule ARGS "@streq redirect302" "id:2,phase:2,status:302,log,redirect:http://www.coraza.io"
                SecRule ARGS "@streq block401" "id:3,phase:2,status:401,deny,log"
                SecRule ARGS "@streq block403" "id:4,phase:2,status:403,deny,log"
            ';
        }
        location /phase3 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecDefaultAction "phase:1,log,auditlog,pass"
                SecDefaultAction "phase:2,log,auditlog,pass"
                SecRule ARGS "@streq redirect301" "id:1,phase:3,status:301,log,redirect:http://www.coraza.io"
                SecRule ARGS "@streq redirect302" "id:2,phase:3,status:302,log,redirect:http://www.coraza.io"
                SecRule ARGS "@streq block401" "id:3,phase:3,status:401,deny,log"
                SecRule ARGS "@streq block403" "id:4,phase:3,status:403,deny,log"
            ';
        }
        location /phase4 {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecDefaultAction "phase:1,log,auditlog,pass"
                SecDefaultAction "phase:2,log,auditlog,pass"
                SecRule ARGS "@streq redirect301" "id:1,phase:4,status:301,log,redirect:http://www.coraza.io"
                SecRule ARGS "@streq redirect302" "id:2,phase:4,status:302,log,redirect:http://www.coraza.io"
                SecRule ARGS "@streq block401" "id:3,phase:4,status:401,deny,log"
                SecRule ARGS "@streq block403" "id:4,phase:4,status:403,deny,log"
            ';
        }
        location /early-block {
            coraza on;
            coraza_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecDefaultAction "phase:1,log,auditlog,pass"
                SecDefaultAction "phase:2,log,auditlog,pass"
                SecAction "id:900101,phase:1,nolog,pass,t:none,setvar:tx.trigger_phase1=1"
                SecAction "id:900103,phase:1,nolog,pass,t:none,setvar:tx.trigger_phase3=1"
                SecAction "id:900105,phase:1,nolog,pass,t:none,setvar:tx.trigger_phase5=1"
                SecRule TX:TRIGGER_PHASE1 "@eq 1" "id:901111,phase:1,t:none,deny,log"
                SecRule REQUEST_BODY "@rx attack" "id:901121,phase:2,t:none,deny,log"
                SecRule TX:TRIGGER_PHASE3 "@eq 1" "id:901131,phase:3,t:none,deny,log"
                SecRule RESPONSE_BODY "@rx ok" "id:901141,phase:4,t:none,deny,log"
                SecRule TX:TRIGGER_PHASE5 "@eq 1" "id:901151,phase:5,t:none,pass,log,msg:\'This is the phase 5.\'"
            ';
        }
    }
}
EOF

$t->write_file("/phase1", "should be moved/blocked before this.");
$t->write_file("/phase2", "should be moved/blocked before this.");
$t->write_file("/phase3", "should be moved/blocked before this.");
$t->write_file("/phase4", "should not be moved/blocked, headers delivered before phase 4.");
$t->write_file("/early-block", "should be moved/blocked before this.");
$t->run();
$t->todo_alerts();
$t->plan(25);

###############################################################################


# Redirect (302) — status code + Location header
my $r302p1 = http_get('/phase1?what=redirect302');
like($r302p1, qr/^HTTP.*302/, 'redirect 302 - phase 1');
like($r302p1, qr/Location: http:\/\/www\.coraza\.io/, 'redirect 302 location header - phase 1');
my $r302p2 = http_get('/phase2?what=redirect302');
like($r302p2, qr/^HTTP.*302/, 'redirect 302 - phase 2');
like($r302p2, qr/Location: http:\/\/www\.coraza\.io/, 'redirect 302 location header - phase 2');
my $r302p3 = http_get('/phase3?what=redirect302');
like($r302p3, qr/^HTTP.*302/, 'redirect 302 - phase 3');
like($r302p3, qr/Location: http:\/\/www\.coraza\.io/, 'redirect 302 location header - phase 3');
my $r302p4 = http_get('/phase4?what=redirect302');
like($r302p4, qr/^HTTP.*302/, 'redirect 302 - phase 4');
like($r302p4, qr/Location: http:\/\/www\.coraza\.io/, 'redirect 302 location header - phase 4');

# Redirect (301) — status code + Location header
like(http_get('/phase1?what=redirect301'), qr/^HTTP.*301/, 'redirect 301 - phase 1');
like(http_get('/phase2?what=redirect301'), qr/^HTTP.*301/, 'redirect 301 - phase 2');
like(http_get('/phase3?what=redirect301'), qr/^HTTP.*301/, 'redirect 301 - phase 3');
like(http_get('/phase4?what=redirect301'), qr/^HTTP.*301/, 'redirect 301 - phase 4');

# Block (401)
like(http_get('/phase1?what=block401'), qr/^HTTP.*401/, 'block 401 - phase 1');
like(http_get('/phase2?what=block401'), qr/^HTTP.*401/, 'block 401 - phase 2');
like(http_get('/phase3?what=block401'), qr/^HTTP.*401/, 'block 401 - phase 3');
like(http_get('/phase4?what=block401'), qr/^HTTP.*401/, 'block 401 - phase 4');

# Block (403)
like(http_get('/phase1?what=block403'), qr/^HTTP.*403/, 'block 403 - phase 1');
like(http_get('/phase2?what=block403'), qr/^HTTP.*403/, 'block 403 - phase 2');
like(http_get('/phase3?what=block403'), qr/^HTTP.*403/, 'block 403 - phase 3');
like(http_get('/phase4?what=block403'), qr/^HTTP.*403/, 'block 403 - phase 4');

# Nothing to detect
like(http_get('/phase1?what=nothing'), qr/should be moved\/blocked before this./, 'nothing phase 1');
like(http_get('/phase2?what=nothing'), qr/should be moved\/blocked before this./, 'nothing phase 2');
like(http_get('/phase3?what=nothing'), qr/should be moved\/blocked before this./, 'nothing phase 3');
like(http_get('/phase4?what=nothing'), qr/should not be moved\/blocked, headers delivered before phase 4./, 'nothing phase 4');

# early block (https://github.com/SpiderLabs/Coraza-nginx/issues/238)
like(http_get('/early-block'), qr/^HTTP.*403/, 'early block 403 (https://github.com/SpiderLabs/Coraza-nginx/issues/238)');
