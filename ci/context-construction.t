#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use FindBin;
use File::Temp qw(tempdir);
use Text::ParseWords qw(shellwords);

# Compile the real constructor and cleanup against inert allocator/handle
# stubs. No nginx server or libcoraza handle is involved in failure injection.
my $root = "$FindBin::Bin/..";
my $tmp = tempdir(CLEANUP => 1);
open my $source, '<', "$root/src/ngx_http_coraza_module.c" or die $!;
my $code = do { local $/; <$source> };
close $source or die $!;
open my $extracted, '>', "$tmp/context-functions.inc" or die $!;
for my $signature (
    qr/void ngx_http_coraza_cleanup\(void \*data\)/,
    qr/ngx_inline ngx_http_coraza_ctx_t \*\s*ngx_http_coraza_create_ctx\(ngx_http_request_t \*r\)/,
) {
    my @functions = $code =~ /($signature\s*\{.*?^\})/msg;
    @functions == 1 or die "expected exactly one function for $signature\n";
    print {$extracted} "$functions[0]\n" or die $!;
}
close $extracted or die $!;

my @cc = shellwords($ENV{CC} // 'cc');
my @flags = shellwords($ENV{CFLAGS} // '');
my $binary = "$tmp/context-contract";
my $rc = system(@cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
    '-pedantic', @flags, "-I$tmp", "$FindBin::Bin/context-contract.c",
    '-o', $binary);
is($rc, 0, 'constructor contract compiles') or BAIL_OUT('compile failed');
my @info = stat $binary;
diag("constructor binary: $binary; mtime=$info[9]; size=$info[7]");

for my $case (qw(
    context-allocation missing-waf complex-value transaction transaction-id
    cleanup cleanup-with-id id-copy success success-with-id empty-id
    main-waf already-logged
)) {
    is(system($binary, $case), 0, $case);
}
done_testing();
