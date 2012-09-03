#!/usr/bin/perl

use strict;
use warnings;
use diagnostics;

use RDF::Simple::Parser;
use LWP::Simple;
use Text::Diff;
use File::Copy;
use Data::Dumper;
use HTML::LinkExtractor;

=pod

=head1 NAME

dsamon.pl -- monitors Debian Security Advisories and listas available binary packages for a given architecture and distribution

=head1 DESCRIPTION

B<dsamon> is a simple program which monitors Debian Security Advisories, provided by the Debian Security Team in the RDF format. It is aimed to be scriptable, or at least callable from a cron job, and so it provides links to download the updated binary packages for a given architecture and distribution.

It will also exit with an exit code of B<n>, where B<n> is the number of new vulnerabilities since the last run.

=head1 CONFIGURATION

You can set the RDF file in the F<$uri> variable, and the support historic files in F<$newFile> and F<$oldFile>. The distribution and architecture can be set in F<$dist> and F<$arch>, respectively. The code aims to be quite readable, so you can configure whatever you want if you're Perl-aware.

=cut

my $uri = 'http://www.debian.org/security/dsa'; # This is the DSA's RDF file
my $newFile = "/tmp/dsa.new"; # New data will be saved here
my $oldFile = "/tmp/dsa.old"; # Previous data will be saved here
my $dist = "etch"; # Dist
my $arch = "i386"; # Arch
my $debug = 0;

=head1 USAGE

Just run B<./dsamon> or B<perl dsamon> to start it. You should have an Internet connection. L<RDF::Simple::Parser> and L<LWP::Simple> will honour the F<http_proxy> environment variable, so you shouldn't worry about that.

=head1 INTERNALS

B<dsamon> will use L<LWP::Simple> to get the RDF file, which will be parsed using <RDF::Simple::Parser>. It will properly puke on errors which are fatal.

=cut

my $rdf = LWP::Simple::get($uri) or die "[ERR] Can't get $uri: $!\n";
my $parser = RDF::Simple::Parser->new( base => $uri );
my @data = $parser->parse_rdf( $rdf ) or die "[ERR] Can't parse $uri: $!\n";

my %vulns;

=cut

Then, it will search all RDF nodes providing links, and will store them into a hash named F<%vulns>.

=cut

foreach ( @data ) {

	my @data = @{$_};

	if ( $data[1] =~ /link/ ) {

		$vulns{$data[2]} = '1';

	}

}

=cut

A sorted version of the links will be stored to the new file, and it will be compared using L<Text::Diff> to the old file. If the old file does not exist, this defaults to provide all vulnerabilities available in the RDF file.

=cut

open ( NEW, '>', $newFile ) or die "[ERR] Can't open $newFile: $!\n";

	foreach ( sort keys %vulns ) {
		print NEW "$_\n";
	}

close NEW;

my $diff = diff ( $oldFile, $newFile );
copy ( $newFile, $oldFile );

=cut

If differences occur, L<LWP::Simple> will be used to get all the advisory links, and then links will be extracted from the resulting HTML using L<HTML::LinkExtractor>. Links matching binary packages from the given architecture and distribution will be outputted. Also, a vulnerability count will be setup and this will make the final exit code

=cut

if ( defined $diff and $diff ne '' ) {

	my @newVulns;

	foreach ( split ( "\n", $diff ) ) {

		push ( @newVulns, $1) if /^\+(.*security.*dsa.*)$/;

	}

	my $vulnCount = 0;

	foreach my $vuln ( @newVulns ) {

		print "[INF] New vulnerability detected in URI: $vuln. Listing available packages for dist $dist, arch $arch:\n" if $debug;

		my $data = LWP::Simple::get( $vuln ) or die "[ERR] Can't get $vuln: $!\n";
		my $extractor = HTML::LinkExtractor->new;
		$extractor->parse( \$data );

		foreach my $link ( @{ $extractor->links } ) {
			my %element = %{$link};
			next unless defined $element{href} and $element{href} ne '';
			print "   $element{href}\n" if ( $element{href} =~ /.*$dist.*$arch.*deb/ );
		}

		++$vulnCount;

	}

	exit $vulnCount;

} else {

	exit 0;

}

=head1 EXAMPLES

$ for file in `dsamon | grep http | xargs` ; do wget -c $file ; done

=head1 AUTHOR

José Miguel Parrella Romero <bureado@cpan.org>

=head1 LICENSE

This program is free software. It is licensed under the terms of Perl itself.

=cut
