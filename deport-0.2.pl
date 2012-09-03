#!/usr/bin/perl

# deport -> D Easy Port-check (2006)
# this is free for everyone who wants to use it. consider giving back to the sysadmin community
# originally written by Jose Parrella <perl@bureado.com.ve>
# with Gentoo modifications by Julio Ortega and #gentoo @ unplug.org.ve

use strict;

die "You need to be root to run deport\n" unless `id -u` eq "0\n";

my $VERSION = 0.2;

# Executables location
my $netstat = "/bin/netstat";
my $lsof = "/usr/bin/lsof";
my $fuser = "/bin/fuser";
my $md5sum = "/usr/bin/md5sum";

# "apt" for Debian and Debian-based distributions (DSL, Ubuntu, Debian, ...)
# "rpm" for RPM-based distributions (FC, RHEL, CentOS, TinySofa, SuSe, Mandrake, ...)
# "equery" and "epm" for Gentoo and Gentoo-based distributions
my $packageManager = "apt";

# Distribution tools for searching a file in a package
my %distroTools = (
			"apt"		=>	"/usr/bin/dpkg -S",
			"equery"	=>	"/usr/bin/equery -q belongs -ef",
			"epm"		=>	"/usr/bin/epm -qf",
			"rpm"		=>	"/usr/bin/rpm -qf",
);

# Main iteration around netstat -vatun output
# We're interested on lines marked LISTEN

my %ports;

foreach my $line (split("\n", `$netstat -vatun`)) {
	if ($line =~ /.+\:(\d+).+\:.+LISTEN/) {
		my $port = $1;
		if (!system("test -x $lsof")) {
			if ( `$lsof -i :$port 2> /dev/null` =~ /^.+\n\w+\s+(\d+).*/) {
				$ports{$port} = `readlink /proc/${1}/exe`;
			}
		}
		else {
			if ( `$fuser -n tcp $port 2> /dev/null` =~ /.+(\d+)$/) {
				$ports{$port} = `ps -p $1 -o comm= 2> /dev/null`;
			}
			else {
				die "Neither lsof nor fuser are installed.\n";
			}
		}
	}
}

# Once the open port hash has been filled,
# let's check who's to blame.

foreach my $port (keys(%ports)) {
	print "TCP port $port is being used by $ports{$port}\n";
	if ($ARGV[0] eq "-p") {
		if (`which $ports{$port}`) {
			print "\tMD5: ", `$md5sum \`which $ports{$port}\``;
			print "\tPackage: ", `$distroTools{$packageManager} \`which $ports{$port}\``;
			print "\tPlease check with your local distributions tools for MD5 ok-ness\n";
			print "\n";
		}
		else {
			print "\tALERT! Possible compromise. Please check lsof | grep \<filename\> and take action accordingly.\n\n";
		}
	}
	else {
		print "\tNOTICE: deport has not checked MD5 checksums nor package status for this file. Use -p flag or check manually.\n\n";
	}
}

# POD section

=head1 DEPORT

deport.pl - A script for monitoring TCP/UDP open ports in Linux systems and doing some sanity checks on the running processes.

=head1 DESCRIPTION

This script checks for open and listening TCP and UDP ports in a Linux system and uses lsof/fuser to check the owner process. Optionally, it can verify the 
package in which the process belongs and verify MD5 checksums, thus making it a useful tool for checking against forged processes using known ports and also it's 
useful for closing down not-so-secure-by-default port configurations in Linux systems.

=pod OSNAMES

linux

=pod SCRIPT CATEGORIES

Networking
Unix/System_administration

=cut
