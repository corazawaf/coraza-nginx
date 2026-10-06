#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
# The nginx-tests CI directory is a sibling of the checkout's ci/ directory.
exec $^X, "$FindBin::Bin/../ci/delayed-buffer-flags.t";
die "cannot run delayed buffer contract: $!";
