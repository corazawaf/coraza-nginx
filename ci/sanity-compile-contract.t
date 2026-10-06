#!/usr/bin/perl

# Exercise the compile runner with real cc and small, isolated header fixtures.
# The full module compile runs separately against CI's configured nginx tree.
use strict;
use warnings;
use Test::More;
use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use FindBin;

my $fixture = "$FindBin::Bin/../t/coraza-sanity-checks-compile.t";

sub write_file {
    my ($path, $content) = @_;
    open my $fh, '>', $path or die "open $path: $!";
    print {$fh} $content or die "write $path: $!";
    close $fh or die "close $path: $!";
}

sub run_fixture {
    my (%options) = @_;
    my $tmp = tempdir(CLEANUP => 1);
    my $root = "$tmp/module with ' spaces";
    my $nginx = "$root/current configured source";
    my $include = "$root/include";
    make_path("$root/t", "$root/src", "$root/empty-bin",
        "$nginx/objs", "$nginx/src/http/v3", "$include/coraza",
        "$root/nginx-1.28.0/objs");
    copy($fixture, "$root/t/compile.t") or die "copy fixture: $!";
    write_file("$nginx/objs/ngx_auto_config.h", "#define SELECTED_TREE 1\n");
    write_file("$nginx/objs/ngx_auto_headers.h", "/* generated header */\n");
    write_file("$nginx/src/http/v3/ngx_http_v3.h", "/* HTTP/3 include */\n");
    write_file("$include/coraza/coraza.h", "/* coraza include */\n");
    write_file("$root/nginx-1.28.0/objs/ngx_auto_config.h",
        "#error obsolete tree selected\n");
    for my $source (qw(ngx_http_coraza_module.c ngx_http_coraza_header_filter.c)) {
        write_file("$root/src/$source", <<'SOURCE');
#include <ngx_auto_config.h>
#include <ngx_auto_headers.h>
#include <ngx_http_v3.h>
#include <coraza/coraza.h>
#if !SELECTED_TREE || CORAZA_SANITY_CHECKS != 1
#error wrong source selection or compatibility definition
#endif
int compile_fixture;
SOURCE
    }
    if ($options{missing}) {
        unlink "$nginx/objs/$options{missing}" or die "unlink header: $!";
    }
    if ($options{invalid}) {
        write_file("$nginx/objs/ngx_auto_config.h", "#error invalid generated header\n");
    }
    if ($options{compile_error}) {
        write_file("$root/src/ngx_http_coraza_header_filter.c", "#error compile failed\n");
    }

    local %ENV = %ENV;
    delete @ENV{qw(CI TEST_NGINX_SOURCE TEST_LIBCORAZA_INCLUDE)};
    $ENV{TEST_NGINX_SOURCE} = $nginx unless $options{unset};
    $ENV{TEST_NGINX_SOURCE} = "$root/absent" if $options{absent};
    $ENV{TEST_NGINX_SOURCE} = '' if $options{empty};
    $ENV{TEST_LIBCORAZA_INCLUDE} = $options{no_coraza} ? "$root/absent" : $include;
    $ENV{CI} = $options{ci_value} if exists $options{ci_value};
    $ENV{CI} = 'true' if $options{ci};
    $ENV{PATH} = "$root/empty-bin" if $options{no_cc};

    my $pid = open my $child, '-|';
    die "fork: $!" unless defined $pid;
    if (!$pid) {
        open STDERR, '>&', STDOUT or die "redirect stderr: $!";
        exec {$^X} $^X, "$root/t/compile.t" or die "exec perl: $!";
    }
    my $output = do { local $/; <$child> };
    close $child;
    return ($?, $output);
}

subtest 'selected current tree compiles both objects' => sub {
    my ($status, $output) = run_fixture(ci => 1);
    is($status, 0, 'compile succeeds') or diag $output;
    like($output, qr/^ok 1 - src\/ngx_http_coraza_module\.c compiles/m,
        'module compiled with selected headers');
    like($output, qr/^ok 2 - src\/ngx_http_coraza_header_filter\.c compiles/m,
        'header filter compiled with selected headers');
    like($output, qr/^1\.\.2$/m, 'both compile assertions ran');
};

subtest 'unselected local run is explicitly unavailable' => sub {
    my ($status, $output) = run_fixture(unset => 1);
    is($status, 0, 'local opt-out succeeds');
    like($output, qr/^1\.\.0 # SKIP set TEST_NGINX_SOURCE/m, 'explicit skip reason');
};

for my $value ('false', '0', 'off', 'TRUE', '1', '') {
    subtest "CI=$value without selection is a local skip" => sub {
        my ($status, $output) = run_fixture(unset => 1, ci_value => $value);
        is($status, 0, 'local opt-out succeeds');
        like($output, qr/^1\.\.0 # SKIP set TEST_NGINX_SOURCE/m,
            'explicit skip reason');
    };
}

for my $case (
    ['CI without selection', {ci => 1, unset => 1}, qr/TEST_NGINX_SOURCE must name/],
    ['empty selection', {empty => 1}, qr/TEST_NGINX_SOURCE must name/],
    ['absent selected tree', {absent => 1}, qr/missing objs\/ngx_auto_config\.h/],
    ['missing config header', {missing => 'ngx_auto_config.h'}, qr/missing objs\/ngx_auto_config\.h/],
    ['missing platform header', {missing => 'ngx_auto_headers.h'}, qr/missing objs\/ngx_auto_headers\.h/],
    ['invalid generated header', {invalid => 1}, qr/invalid generated header/],
    ['compiler error', {compile_error => 1}, qr/compile failed/],
    ['missing compiler', {no_cc => 1}, qr/cc not found/],
    ['missing coraza headers', {no_coraza => 1}, qr/coraza headers not available/],
) {
    my ($name, $options, $diagnostic) = @{$case};
    subtest $name => sub {
        my ($status, $output) = run_fixture(%{$options});
        ok($status != 0, 'required compile fails');
        unlike($output, qr/# SKIP/, 'failure is not a successful skip');
        like($output, $diagnostic, 'cause is reported');
    };
}

done_testing();
