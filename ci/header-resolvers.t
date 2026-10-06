#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin;
use File::Temp qw(tempdir);
use Text::ParseWords qw(shellwords);

my $nginx = $ENV{TEST_NGINX_SOURCE} // die "TEST_NGINX_SOURCE required\n";
my $tmp = tempdir(CLEANUP => 1);
open my $source, '<', "$FindBin::Bin/../src/ngx_http_coraza_header_filter.c" or die $!;
my $code = do { local $/; <$source> };
close $source or die $!;
open my $out, '>', "$tmp/header-resolvers.inc" or die $!;
for my $name (qw(will_chunk resolv_header_server resolv_header_content_type resolv_header_transfer_encoding resolv_header_vary)) {
    my @functions = $code =~ /(^static ngx_(?:int|flag)_t\nngx_http_coraza_$name\([^\n]*\n\{.*?^\})/msg;
    @functions == 1 or die "expected one $name resolver\n";
    print {$out} $functions[0], "\n" or die $!;
}
close $out or die $!;
my @cc = shellwords($ENV{CC} // 'cc');
my @flags = shellwords($ENV{CFLAGS} // '');
my @includes = map { "-I$nginx/$_" }
    qw(objs src/core src/event src/event/modules src/event/quic src/os/unix
       src/http src/http/modules src/http/v2 src/http/v3);
my $binary = "$tmp/header-resolvers";
is(system(@cc, '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
    @flags, @includes, "-I$tmp", "$FindBin::Bin/header-resolvers.c", '-o', $binary),
    0, 'production resolvers compile') or BAIL_OUT('compile failed');
my @info = stat $binary;
diag("resolver binary: $binary; mtime=$info[9]; size=$info[7]");
is(system($binary), 0, 'response-header boundary and error contracts');
done_testing();
