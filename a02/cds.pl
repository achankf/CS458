#!/bin/perl
use strict;
use warnings;
use diagnostics;

# Auto flush stdout at each print
$| = 1;

# ======== global variables ========
sub getTokens {
	my $file = shift;
	my @ret;
	open(FILE, $file) or die("Unable to open $file");
	@ret = <FILE>;
	close(FILE);
	chomp @ret;
	s/\r//g for(@ret);
	return @ret;
}

my @keywords = getTokens "keywords.txt";
my @domains = getTokens "domains.txt";

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

			# concat addresses in sorted order
			$buffer .= join(", ", (sort {
				my @a = split /\./, $a;
				my @b = split /\./, $b;
				$a[0] <=> $b[0] or 
				$a[1] <=> $b[1] or 
				$a[2] <=> $b[2] or 
				$a[3] <=> $b[3];} 
				# search for addresses in the given line
				($line =~ m/A (\d+.\d+.\d+.\d+)/g)));
			# end of concat addresses

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
