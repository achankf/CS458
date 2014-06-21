#!/bin/perl
use strict;
use warnings;
use diagnostics;

# Auto flush stdout at each print
$| = 1;

my @ban_ip = (
	# hackforums.net
	"141.101.121.10",
	"141.101.121.11",
	"141.101.121.12",
	"141.101.121.13",
	"141.101.121.9",
	# Makezine.com
	"192.0.80.250",
	"192.0.81.250",
	"66.155.11.238",
	"66.155.9.238",
	"76.74.254.120",
	"76.74.254.123",
	# Hackaday.com
	"192.0.82.250",
	"192.0.83.250",
	"66.155.11.244",
	"66.155.9.244",
	"76.74.255.117",
	"76.74.255.123",
	# Vcdquality.com
	"208.93.110.120",
	# Securityfocus.com
	"143.127.139.110",
	# hakin9.com
	"148.251.235.73",
	# Blackhat.com
	"141.101.123.223",
	"190.93.240.223",
	# Sectools.org
	"173.255.243.189",
	# Hackedgadgets.com
	"74.208.123.111",
	# torproject.org
	"38.229.72.16",
	"82.195.75.101",
	"86.59.30.40",
	"93.95.227.222",
	"38.229.72.14",
	# gmail.com
   "74.125.226.118",
   "74.125.226.117",
	# p.r.im
  "54.243.190.39",
);

my @ban_ip_range = (
	"74[.]125[.]\\d+[.]\\d+",
	"216[.]239[.]32[.]\\d+/"
);

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
		if ($line =~ /(\d+.\d+.\d+.\d+).(\d+) >.*q: A\? $domain./) {
			$buffer = "[Censored domain name lookup]: domain:$domain, src:$1:$2, host:";

			# get rid of anything nameserver-related
			$line =~ s/ns: .*//;

			# concat addresses in sorted order
			$buffer .= join(", ", (sort {
				my @a = split /\./, $a;
				my @b = split /\./, $b;
				$a[0] <=> $b[0] or
				$a[1] <=> $b[1] or
				$a[2] <=> $b[2] or
				$a[3] <=> $b[3];
			}
			# search for addresses in the given line
			($line =~ m/A (\d+.\d+.\d+.\d+)/g)));
			# end of concat addresses

			# print the buffer and autoflush
			print "$buffer\n";
		}
	}
}

sub checkIP {
	my ($second, $buffer) = @_;

	for my $ip (@ban_ip) {
		if ($second =~ /($ip)/) {
			print "$1\n";
		}
	}

	for my $range (@ban_ip_range) {
		if ($second =~ /($range)/) {
			print "$1\n";
		}
	}
}

sub runAll {
	my ($first, $second, $buffer) = @_;
	checkDNSLookup $second;
	checkIP $second, $buffer;
}

sub processAll {
}

# ======== ``main" runner ========

my $first;
my $second;
my $payload;

# run runAll for each line from STDIN
while (my $line = <>) {

	chomp $line;

	if ($line =~ /^[ ]/) {
		$second = $line;
	} elsif ($line =~ /^\t/) {
		# push @buffer, substr $line, 51;
		$payload .= substr $line, 51;
	} else {
		if (defined $first) {
			runAll $first, $second, $payload;
		}
		$payload = "";
		$first = $line;
	}
}
			print "$first\n";
			print "$second\n";
			print "$payload\n";
#runAll $_ for <>;
