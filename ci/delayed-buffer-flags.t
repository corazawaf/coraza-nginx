#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin;
use File::Temp qw(tempdir);
use Text::ParseWords qw(shellwords);

my $root = "$FindBin::Bin/..";
my $nginx = $ENV{TEST_NGINX_SOURCE}
    // die "TEST_NGINX_SOURCE must name a configured nginx tree\n";
my $tmp = tempdir(CLEANUP => 1);
open my $source, '<', "$root/src/ngx_http_coraza_body_filter.c" or die $!;
my $code = do { local $/; <$source> };
close $source or die $!;
# The eight-space indentation uniquely identifies the per-buffer delayed block.
# Execute that exact block; do not maintain a second copy of the algorithm.
my @blocks = $code =~ /(^        if \(ctx->headers_delayed\) \{.*?^        \})/msg;
@blocks == 1 or die "expected exactly one delayed buffer block\n";
open my $out, '>', "$tmp/delayed-buffer.inc" or die $!;
print {$out} $blocks[0] or die $!;
close $out or die $!;
my @cc = shellwords($ENV{CC} // 'cc');
my @flags = shellwords($ENV{CFLAGS} // '');
my @includes = map { "-I$nginx/$_" }
    qw(objs src/core src/event src/event/modules src/event/quic src/os/unix
       src/http src/http/modules src/http/v2 src/http/v3);
my $binary = "$tmp/delayed-buffer-contract";
is(system(@cc, '-O2', '-Wall', '-Wextra', '-Werror', @flags, @includes,
    "-I$tmp", "$FindBin::Bin/delayed-buffer-contract.c", '-o', $binary),
    0, 'delayed buffer contract compiles') or BAIL_OUT('compile failed');
my @info = stat $binary;
diag("delayed buffer binary: $binary; mtime=$info[9]; size=$info[7]");
is(system($binary), 0, '52 marker, data, final, file, bypass and failure cases');
done_testing();
