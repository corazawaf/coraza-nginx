#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
$ENV{CORAZA_NGINX_TEST_ROOT} = $FindBin::Bin if -d "$FindBin::Bin/lib";
exec $^X, "$FindBin::Bin/../ci/header-transform-body.t";
die "exec failed: $!";
