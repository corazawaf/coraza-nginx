#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
exec $^X, "$FindBin::Bin/../ci/delayed-buffer-runtime.t";
die "cannot run delayed buffer runtime: $!";
