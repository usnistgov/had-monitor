#!/usr/bin/perl

#  had-monitor.pl
#
#   walks the .gov TLD using dnsfunnel on signed zones looking for PMTU issues
#   Scott Rose, NIST
#   6/27/12
use Net::DNS;
use Net::DNS::SEC;
use Net::DNS::Resolver;
use Time::Local;
use Getopt::Long;

$name;
@line; 
my $testRes;
my $inputFile = '';
my $outputFile = '';

#Options:
#  --input : The input file
#  --output : The output file

GetOptions('input=s' => \$inputFile,     #input file
           'output=s' => \$outputFile);             #output file

if($inputFile) {
	open(LIST, $inputFile) || die "Cannot open delegation request";
}

my $testRes = Net::DNS::Resolver->new(
 	nameservers => ["127.0.0.1"],
 	recurse     => 1,
  	debug       => 0,
  	udp_timeout => 5,
  	tcp_timeout => 8,
  );
$testRes->cdflag(1);
$testRes->dnssec(1);

if ($outputFile) {
		open (OUTPUT, ">" . $outputFile) || die "can't open output file";
	} else {
		($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
		$outputFile = ">" . ($year + 1900) . $mon . $mday;
		open (OUTPUT, $outputFile) || die "can't open default output file";
}

while (<LIST>) {
	chomp($_);
	@line = split(/,/, $_);
	  #the zone name
	if (@line[1] == 1) {   #one of the zones to test?
		$DNSSEC_results = do_DNSSEC_Tests(@line);
	}
	#now print out the results
	print OUTPUT $DNSSEC_results  . "\n";
	
}

close LIST;
close OUTPUT;

sub do_DNSSEC_Tests() {
	my @input = @_;
	my $secName = @input[0];
	my $retString;
	$testRes->dnssec(1);
	$testRes->cdflag(0);

	$retString = $secName . ",";
	my $reply = $testRes->send($secName, 'DNSKEY');

	if ($reply ne undef) {
		my $header = $reply->header;
		if (($header->rcode eq "NOERROR") && ($header->ancount > 0)) {
			if ($header->ad == 1) {
				$retString .= "1," . @input[2] . "," . @input[3] . "," . @input[4] . ",1,V,";
			} else {
				$retString .= "1," . @input[2] . "," . @input[3] . "," . @input[4] . ",1,I,";
			}
			my @ansSec = $reply->answer;
			my $keyRR;
			foreach $keyRR (@ansSec) {
				if ($keyRR->type eq "DNSKEY") {
					$retString .= $keyRR->algorithm . ",";
					return $retString;
				}
			}
		} elsif ($header->rcode eq "NXDOMAIN") {
			return "0," . @input[2] . "," . @input[3] . "," . @input[4] . ",NXDOMAIN";	
		} elsif ($header->rcode eq "SERVFAIL") {
			$testRes->cdflag(1);
			#servfail - could be validation Failure
			$reply = $testRes->send($secName, 'DNSKEY');
			if ($reply ne undef) {
				my $CDheader = $reply->header;
				if (($CDheader->rcode eq "NOERROR") && ($CDheader->ancount > 0)) {
					$retString .= "1," . @input[2] . "," . @input[3] . "," . @input[4] . ",";
					my @CDansSec = $reply->answer;
					foreach $keyRR (@ansSec) {
						if ($keyRR->type eq "DNSKEY") {
							$retString .= "1,B," . $keyRR->algorithm . ",";
							return $retString;
						}
					}
                    $retString .= "0,0,0,";
				} elsif ($CDheader->rcode eq "SERVFAIL") {
					$retString .= "0," . @input[2] . "," . @input[3] . "," . @input[4] . ",0,0,0,";
				}
			}
		} elsif (($header->rcode eq "NOERROR") && ($header->ancount == 0)) {
			#zone is not signed, or Name error (from signed parent);
			if ($header->nscount > 0) {
				@ansSec = $reply->authority;
				my $first = @ansSec[0];
				if ($first->name ne $secName) {
					$retString .= "0," . @input[2] . "," . @input[3] . "," . @input[4] . ",NXDOMAIN";
				} else {
					$retString .= "1," . @input[2] . "," . @input[3] . "," . @input[4] . ",0,0,0,";
				}
			} else  {
				$retString .= "0," . @input[2] . "," . @input[3] . "," . @input[4] . ",0,0,0,";
			}
		}

	} else {
		$retString .= "0," . @input[2] . "," . @input[3] . "," . @input[4] . ",0,0,0,";
	}
	$testRes->cdflag(1);
	return $retString;

}


