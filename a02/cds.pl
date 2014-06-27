#!/bin/perl
use strict;
use warnings;
use diagnostics;

# Auto flush stdout at each print
$| = 1;

my %ban_ip = (
	#Vcdquality.com
	"208.93.110.120" => "Vcdquality.com",
	#Securityfocus.com
	"143.127.139.110" => "Securityfocus.com",
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
@keywords = sort @keywords;

# ======== helpers ========

# check for DNS lookup
sub checkDNSLookup {
	my $second = shift;
	my $buffer;
	foreach my $domain(@domains) {
		if ($second =~ /(\d+.\d+.\d+.\d+).(\d+) >.*q: A\? $domain./) {
			$buffer = "[Censored domain name lookup]: domain:$domain, src:$1:$2, IP(s):";

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

	if ($second =~ /(\d+.\d+.\d+.\d+).(\d+) > (\d+.\d+.\d+.\d+)/) {
		my $clientIP = $1;
		my $clientPort = $2;
		my $banIP = $3;
		for my $domain (@domains) {
			if ($buffer =~ /[Hh][Oo][Ss][Tt]: $domain/) {
				print "[Censored domain connection attempt]: src:$clientIP:$clientPort, host:$banIP, domain:$domain\n";
				return 0;
			}
		}

		for my $ip (keys %ban_ip) {
			if ($buffer =~ /[Hh][Oo][Ss][Tt]: $ip/) {
				print "[Censored domain connection attempt]: src:$clientIP:$clientPort, host:$banIP, domain:" . $ban_ip{$ip} . "\n";
				return 0;
			}
		}
	}
	return 1;
}

sub censoredURL {
	my $payload = shift;
	my $buffer;

	if ($payload =~ /(?:GET|POST|PUT|DELETE|HEAD) ((\/*[-_.\w\d]*)+)\s/) {
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

		if ($payload =~ /[hH][oO][sS][tT]: (([.]*\w+)+)/) {
			my $domain = $1;
			$buffer .= "[Censored Keyword - URL]: URL:$domain$request, keyword(s):";
			$buffer .= join ", ", @found_words;
			print "$buffer\n";
			return 0;
		}
	}
	return 1;
}

sub censoredPayload {
	my ($second, $payload) = @_;
	my $buffer;
	my @found_words;

	if ($second =~ /\d+.\d+.\d+.\d+.\d+ > \d+.\d+.\d+.\d+.(\d+).*A\?/) {
		#if ($1 == 53) {
			return 1;
		#}
	}

	for my $keyword (@keywords) {
		# match once
		if ($payload =~ /[^a-zA-Z0-9-]$keyword[^a-zA-Z0-9-]/) {
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

sub blockTorDownload {
	my ($second, $payload) = @_;
	my $buffer;
	my $method;
	my $domain;
	my $request;

	# avoid searching in payload if the packet is a DNS lookup
	if ($second =~ /\d+.\d+.\d+.\d+.\d+ > \d+.\d+.\d+.\d+.(\d+).*A\?/) {
		return 1;
	} elsif ($payload =~ /GET ((\/*[-_.\w\d]*)*tor[._-]*browser[\w.-]*(?:exe|dmg|tar[.]xz))/) {
		$request = $1;
		$method = "HTTP";
		if ($payload =~ /[hH][oO][sS][tT]: (([.]*\w+)+)/) {
			$domain = $1;
		} else {
			return 1;
		}
	} else {
		return 1;
	}

	print "[Tor download attempt]: Method:$method, Address:$domain$request\n";
	return 0;
}

sub runAll {
	my ($first, $second, $payload) = @_;
	# only one alert per packet
	(checkDNSLookup $second)
		&& (checkIP $second, $payload)
		&& (censoredURL $payload)
		&& (censoredPayload $second, $payload)
		&& (blockTorDownload $second, $payload);
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
		my $temp = substr $line, 10, 39;
		while ($temp =~ /([a-zA-Z0-9][a-zA-Z0-9])/g) {
			$payload .= chr(hex($1));
		}
	} else {
		if (defined $first && defined $second) {
			runAll $first, $second, $payload;
#print "BEGIN======\n$payload\n";
		}
		$first = $line;
		undef $second;
		undef $payload;
	}
}
if (defined $first && defined $second) {
	runAll $first, $second, $payload;
#print "BEGIN======\n$payload\n";
}
