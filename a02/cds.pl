#!/bin/perl
use strict;
use warnings;
use diagnostics;

# Auto flush stdout at each print
$| = 1;

# ======== global variables ========
open(FILE, "keywords.txt") or die("Unable to open keywords.txt");
my @keywords = <FILE>;
close(FILE);

# clean up keywords
chomp @keywords;
s/\r//g for(@keywords);

open(FILE, "domains.txt") or die("Unable to open domains.txt");
my @domains = <FILE>;
close(FILE);

# clean up domains
chomp(@domains);
s/\r//g for(@domains);

# ======== helpers ========

# check for DNS lookup
sub checkDNSLookup {
	my $line = shift;
	my $buffer;
	foreach my $domain(@domains) {
		if ($line =~ /(\d+.\d+.\d+.\d+).(\d+) >.*q: A\? .*$domain./) {
			$buffer = "[Censored domain name lookup]: domain:$domain, src:$1:$2, host:";

			# get rid of anything nameserver-related
			$line =~ s/ns:.*//;

			my @bad_ip;
			foreach my $matched ($line =~ m/A (\d+.\d+.\d+.\d+)/g) {
				push @bad_ip, $matched;
			}

			# concat addresses in sorted order
			$buffer .= join(", ", (sort {
				my @a = split /\./, $a;
				my @b = split /\./, $b;
				$a[0] <=> $b[0] or 
				$a[1] <=> $b[1] or 
				$a[2] <=> $b[2] or 
				$a[3] <=> $b[3];} @bad_ip));

			# print the buffer and autoflush
			print "$buffer\n\n\n";
		}
	}
}

sub runAll {
	my $line = shift;
	checkDNSLookup $line;
}

# ======== ``main" runner ========

# run runAll for each line from STDIN
runAll $_ for <>;
