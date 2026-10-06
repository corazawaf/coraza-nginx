#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
exec $^X, "$FindBin::Bin/../ci/header-resolvers.t";
die "cannot run header resolver contracts: $!";
