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
	# google
	"216[.]239[.]32[.]\\d+",
	"64[.]244[.]160[.]\\d+",
	"66[.]249[.]80[.]\\d+",
	"72[.]14[.]192[.]\\d+",
	"209[.]85[.]128[.]\\d+",
	"65[.]102[.]\\d+[.]\\d+",
	"74[.]125[.]\\d+[.]\\d+",
	"64[.]18[.]\\d+[.]\\d+",
	"207[.]126[.]144[.]\\d+",
	"173[.]194[.]\\d+[.]\\d+",
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
	my $second = shift;
	my $buffer;
	foreach my $domain(@domains) {
		if ($second =~ /(\d+.\d+.\d+.\d+).(\d+) >.*q: A\? $domain./) {
			$buffer = "[Censored domain name lookup]: domain:$domain, src:$1:$2, host:";

			# get rid of anything nameserver-related
			$second =~ s/ns: .*//;

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
			($second =~ m/A (\d+.\d+.\d+.\d+)/g)));
			# end of concat addresses

			# print the buffer and autoflush
			print "$buffer\n";
			return 0;
		}
	}
	return 1;
}

sub checkIP {
	my ($second, $buffer) = @_;

	for my $ip (@ban_ip) {
		if ($second =~ /(\d+.\d+.\d+.\d+).(\d+) > ($ip)/) {
			my $clientIP = $1;
			my $clientPort = $2;
			my $banIP = $3;
			for my $domain (@domains) {
				if ($buffer =~ /($domain)/) {
					print "[Censored domain connection attempt]: src:$clientIP:$clientPort, host:$banIP, domain:$1\n";
					return 0;
				}
			}
		}
	}
	return 1;
}

sub censoredURL {
	my $payload = shift;
	my $buffer;

	if ($payload =~ /GET[.]((\/*[-_\w]+)+)[.]/) {
		my $request = $1;
		my @found_words = ();

		for my $keyword (@keywords) {
			# match once
			if ($request =~ /[-_\/]$keyword[-_\/]/) {
				push @found_words, $keyword;
			}
		}

		if (!@found_words) {
			return 1;
		}

		if ($payload =~ /Host:[.](([.]*\w+)+)[.]/) {
			my $domain = $1;
			$buffer .= "[Censored Keyword - URL]: URL:$domain$request, keyword(s):";
			$buffer .= join ", ", @found_words;
			print "$buffer\n";
			return 0;
		}
		return 1;
	}
	return 1;
}

sub censoredPayload {
	my ($second, $payload) = @_;
	my $buffer;
	my @found_words;

	for my $keyword (@keywords) {
		# match once
		if ($payload =~ /[.]$keyword[.]/) {
			push @found_words, $keyword;
		}
	}

	if (!@found_words) {
		return 1;
	}

	$second =~ /(\d+.\d+.\d+.\d+).(\d+) >/;
	my $host = $1;
	my $port = $2;

	$buffer .= "[Censored Keyword - Payload]: src:$host:$port, keyword(s):";
	$buffer .= join ", ", @found_words;
	print "$buffer\n";
}

sub runAll {
	my ($first, $second, $payload) = @_;
	# only one alert per packet
	(checkDNSLookup $second)
		&& (checkIP $second, $payload)
		&& (censoredURL $payload)
		&& (censoredPayload $second, $payload);
}

# ======== ``main" runner ========

my $first;
my $second;
my $payload;

# run runAll for each second from STDIN
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
runAll $first, $second, $payload;
