#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin;
use File::Temp qw(tempdir);
use Text::ParseWords qw(shellwords);

# Exercise the production function with real nginx header/list types and list
# traversal. Only pool allocation and the Coraza intervention are controlled.
my $root = "$FindBin::Bin/..";
my $nginx = $ENV{TEST_NGINX_SOURCE} // die "TEST_NGINX_SOURCE must name a configured nginx tree\n";
my $tmp = tempdir(CLEANUP => 1);
open my $source, '<', "$root/src/ngx_http_coraza_module.c" or die $!;
my $code = do { local $/; <$source> };
close $source or die $!;
my @functions = $code =~ /(ngx_inline ngx_int_t\s+ngx_http_coraza_process_intervention\(.*?^\})/msg;
@functions == 1 or die "expected exactly one intervention function\n";
open my $extracted, '>', "$tmp/intervention.inc" or die $!;
print {$extracted} $functions[0] or die $!;
close $extracted or die $!;
my @cc = shellwords($ENV{CC} // 'cc');
my @flags = shellwords($ENV{CFLAGS} // '');
my @includes = map { "-I$nginx/$_" }
    qw(objs src/core src/event src/event/modules src/event/quic src/os/unix src/http
       src/http/modules src/http/v2 src/http/v3);
my $binary = "$tmp/location-contract";
is(system(@cc, '-O2', '-Wall', '-Wextra', '-Werror', '-ffunction-sections',
    '-fdata-sections', @flags, @includes, "-I$tmp",
    "$FindBin::Bin/location-contract.c", "$nginx/src/core/ngx_list.c",
    "$nginx/src/core/ngx_string.c", '-Wl,--gc-sections', '-o', $binary),
    0, 'intervention contract compiles') or BAIL_OUT('compile failed');
my @info = stat $binary;
diag("intervention binary: $binary; mtime=$info[9]; size=$info[7]");
for my $case (qw(replace-many replace-empty replace-inactive status-301 status-303
    status-307 status-308 empty-target control-byte del-byte push-failure
    list-part-failure list-storage-failure no-early-log value-failure deny no-data ok no-intervention no-context already-sent)) {
    is(system($binary, $case), 0, $case);
}
done_testing();
