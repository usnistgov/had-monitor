#!/usr/bin/perl

#  had-monitor.pl
#
#   walks the .gov TLD using dnsfunnel on signed zones looking for PMTU issues
#   Scott Rose, NIST
#   6/27/12
use Net::Telnet;
use Net::DNS;
use Net::DNS::SEC;
use Net::DNS::Resolver;
use Time::Local;
use Getopt::Std;
use LWP::UserAgent;
use LWP::Protocol::https;

$name;
@line; 
my $testRes;
my $inputFile = '';
my $outputFile = '';
my $fulltest = '';

#Options:
#  --input : The input file
#  --output : The output file

GetOptions('input=s' => \$inputFile,     #input file
           'output=s' => \$outputFile,             #output file
           'full' => \$fulltest);

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
    $web_results = = @line[0] . "," . @line[1] . "," . @line[2] . "," . @line[3] . "," . @line[4] . ",";
	  #the zone name
	if (@line[1] == 1) {   #one of the zones to test?
        sleep(2);
        if ($fulltest) {
            $web_results .= do_web_Tests(@line[0], @line[4]);
        } else {
            $web_results = @line[13] . "," . @line[14] . "," . @line[15] . ",";
        }
		
    } else {
        $web_results .= "0,0,0,";
    }
	#now print out the results
	print OUTPUT  $web_results . " \n";
	
}

close LIST;
close OUTPUT;

sub do_web_Tests() {
	$qname = @_[0];
	$givenURL = @_[1];
	$webHost = substr(@_[1], 7);
	$useSSL = undef;
	$websrv = "0,";
	$useSSL = "0,";

	#first is the URL we have an actual web server or an alias
	my $ua = LWP::UserAgent->new;
 	$ua->timeout(10);
 	$ua->agent('Mozilla/5.0');
 	$ua->env_proxy;
 	my $reply = $testRes->send($webHost, A);
 	if ($reply ne undef) {
 	#    my $webHeader = Net::DNS::Header->new;
		my $webHeader = $reply->header;
		if ($webHeader->rcode eq "NOERROR") {
			@webAn = $reply->answer;
			foreach $anRR (@webAn) {
				if ($anRR->type eq "CNAME") {
					$webnew = $anRR->cname;
					if (($webnew =~ /edgesuite/) ||
						($webnew =~ /speedera/)  ||
						($webnew =~ /akamai/)  ||
						($webnew =~ /akamaiedge/) ||
						($anRR->ttl < 120) ) {
						$websrv = "CDN,"; 
				    } elsif (!($webnew =~ /$qname/)) {
						return "RE,-,0,";
					} 
				}
			}
		}
	}
 	my $response = $ua->get($givenURL);
 	if ($response->is_redirect) {
 		@redirs = $response->redirects;
 		foreach $rURL (@redirs) {
 		    if (!($rURL =~ /$qname/)) {
 		    	$websrv = "RE,";
 		    } 
 		   	if ($rURL =~ /https:/) {
 		   		$useSSL = 1;
 		   	}
 		}
 	} elsif ($response->is_success) {
 	   if ($websrv ne "CDN,") {
 	   		$websrv = "1,";
 		}
 	} elsif ($response->is_error) {
 	    $websrv = $response->code . ",";
 	} else {
 	    $websrv = "0,";
 	}
	
	#Does it use SSL?
	if ($useSSL eq undef) {	
		$ua->protocols_allowed( ['https'] );
		$httpsResp = $ua->get("https://" . $webHost);
		if ($httpsResp->is_success) {
 		   $useSSL = "1,";
 		}
 		else {
 		    $useSSL = "0,";
 		}
	}
	
	#Does it have a CERT or TLSA RR?
	$certusage = find_TLSA_or_CERT($webHost, 443);
	
	return $websrv . $useSSL . $certusage;
}

sub find_TLSA_or_CERT() {
	my $qname = @_[0];
	my $portn = @_[1];
	my $reply;
	my $retStr = "0,";
	my $header;
	my @anSec;
	my $rr;
	
	#now look for CAA since it's pretty easy too
	$tlsaQ = "_" . $portn . "._tcp." . $qname;
	$reply = $testRes->send($tlsaQ, 'TLSA');
	if ($reply ne undef) {
		$header = $reply->header;
		if (($header->rcode eq "NOERROR") && ($header->ancount > 0)) { 
			@anSec = $reply->answer;
			foreach $rr (@anSec) {
				if ($rr->type eq 'TLSA') {	
						$retStr = "TLSA,";
				}
			}
		}
	
	}
	
	return $retStr;
}
