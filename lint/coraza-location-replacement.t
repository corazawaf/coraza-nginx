#!/usr/bin/perl

# Static regression checks for Location replacement in process_intervention.

###############################################################################

use warnings;
use strict;

use Test::More;
use FindBin;

###############################################################################

my $root = "$FindBin::Bin/..";
my $src = slurp("$root/src/ngx_http_coraza_module.c");

my $body = '';
if ($src =~ /^(ngx_http_coraza_process_intervention\s*\(.*?^\})/ms) {
	$body = $1;
}
$body =~ s{/\*.*?\*/}{}gs;
$body =~ s{//[^\n]*}{}g;

ok(length $body, 'process_intervention body is extracted');

like($body,
	qr/\bh\s*=\s*ngx_list_push\(&r->headers_out\.headers\);\s*if\s*\(h\s*==\s*NULL\)\s*\{\s*coraza_free_intervention\(intervention\);\s*return\s+NGX_HTTP_INTERNAL_SERVER_ERROR;\s*\}/s,
	'header list push failure frees the intervention and returns an error');

like($body,
	qr/\bh->value\.data\s*=\s*ngx_pnalloc\(r->pool,\s*len\);\s*if\s*\(h->value\.data\s*==\s*NULL\)\s*\{\s*coraza_free_intervention\(intervention\);\s*return\s+NGX_HTTP_INTERNAL_SERVER_ERROR;\s*\}/s,
	'Location value allocation failure frees the intervention and returns an error');

like($body,
	qr/for\s*\(part\s*=\s*&r->headers_out\.headers\.part;.*?"Location".*?\.hash\s*=\s*0;.*?r->headers_out\.location\s*=\s*h;/s,
	'existing Location headers are retired before the new one is published');

like($body,
	qr/for\s*\(part\s*=\s*&r->headers_out\.headers\.part;.*?\.hash\s*=\s*0;.*?\bh->hash\s*=\s*1;\s*r->headers_out\.location\s*=\s*h;/s,
	'new Location is marked live only after old ones are retired');

unlike($body,
	qr/r->headers_out\.location\s*=\s*h;.*?\.hash\s*=\s*0;/s,
	'no Location is retired after the new one is published');

unlike($body,
	qr/\bh->hash\s*=\s*1;.*?\.hash\s*=\s*0;/s,
	'new Location is not published before the retire loop');

done_testing();

###############################################################################

sub slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "open $path: $!";
	local $/ = undef;
	return <$fh>;
}
