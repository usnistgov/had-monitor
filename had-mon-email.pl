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
use Getopt::Long;
use LWP::UserAgent;
use LWP::Protocol::https;

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
    $email_results = @line[0] . "," . @line[1] . "," . @line[2] . "," . @line[3] . "," . @line[4] . ",";
	if (@line[1] == 1) {   #one of the zones to test?
		sleep(2);
        	$spfVal = do_spf_test(@line[0]);
        	if ($spfVal ne "N,") {
            		$dkimVal = do_dkim_test(@line[0], @line[9]);
            		$dmarcVal = do_dmarc_test(@line[0]);
            		$tlsaVal = do_dane_test(@line[0]);
            		$email_results .= $spfVal . $dkimVal . $dmarcVal . $tlsaVal . "na,";
        	} else {
            		$email_results .= “0,?,0,0,na,";
        	}
    } else {
        $email_results .= “0,?,0,0,na,";
    }
	#now print out the results
	print OUTPUT $email_results . "\n";
	
	
}

close LIST;
close OUTPUT;

sub do_spf_test() {
	my $zone = @_[0];
	my $spfReply = $testRes->send($zone, 'TXT');
	my @ansSet;
	my $spfrr;
	my $rdataStr;
	
	if ($spfReply ne undef) {
	 	my $nsHeader = $spfReply->header;
		if (($nsHeader->rcode eq "NOERROR") && ($nsHeader->ancount != 0)) {
			@ansSet = $spfReply->answer;
			foreach $spfrr (@ansSet) {
			#here is where we parse the data in the Record
				$rdataStr =  $spfrr->string();   #lc(join(" ", $sfprr->char_str_list()));
				if (($rdataStr =~ /v=spf1/) || ($dataStr =~ /V=SPF1/)) {
					if ($rdataStr =~ /v=spf1 -all/) {
						#domain does not send mail
						return "NS,";
					} else {
						return "SPF,";
					} 
				}
			} 
			return "0,";
		} elsif ($nsHeader-rcode eq "NOERROR")  && ($nsHeader->ancount == 0) {
			return "0,";
        } elsif (($nsHeader-rcode eq "NXDOMAIN") || ($nsHeader-rcode eq "SERVFAIL")){
            return "N,";
        }
	}
    return "N,";
}

sub do_dkim_test() {
	my $zone = @_[0];
	my $selectVal = @_[1];
	my @ans;
	my $query = $selectVal . "._domainkey." . $zone;
	my $retString = "?,";
	my $dkimrr;
	
	if ($selectVal ne '?') {
		my $dkimReply = $testRes->send($query, 'TXT');
		if ($dkimReply ne undef) {
		 	my $dkHeader = $dkimReply->header;
			if (($dkHeader->rcode eq "NOERROR") && ($dkHeader->ancount != 0)) {
				@ans = $dkimReply->answer;
				foreach $dkimrr (@ans) {
					if ($dkimrr->type eq 'TXT') {
						$retString =  $selectVal . ",";
					}
				}
			} 
		} 
	}
	return $retString;
}



sub do_dmarc_test() {
	my $zone = @_[0];
	my $qname = "_dmarc." . $zone;
	my $dmRR;
	
	my $mydmarcReply = $testRes->send($qname, 'TXT');
	if ($mydmarcReply ne undef) {
		my $nsHeader = $mydmarcReply->header;
		if (($nsHeader->rcode eq "NOERROR") && ($nsHeader->ancount != 0)) {
			my @ansSec = $mydmarcReply->answer;
			foreach $dmRR (@ansSec) {
				#make sure it is a DMARC TXT RR and not a wildcard SPF RR or something.
				if ($dmRR->type eq 'TXT') {
					my $drdatastr = $dmRR->string;
					if (($drdatastr =~ /v=DMARC1/) || ($drdatastr =~ /v=dmarc1/)) {
						return "1,";
					}
				}
			} 
            return "0,";
        } else {
			return "0,";
		}
	}
    return "0,";
}

sub do_dane_test() {
	my $zone = @_[0];
    my $mxRR;
	
	#first get the MX for the zone (if available)
	my $reply = $testRes->send($zone, 'MX');
	if ($reply ne undef) {
		my $smHeader = $reply->header;
		if (($smHeader->rcode eq "NOERROR") && ($smHeader->ancount > 0)) {
			my @MXans = $reply->answer;
			foreach $mxRR (@MXans) {
					if ($mxRR->type eq 'MX') {
						$tlsaQ = "_" . $portn . "._tcp." . $mxRR->exchange;
						$reply = $testRes->send($tlsaQ, 'TLSA');
						if ($reply ne undef) {
                            $header = $reply->header;
                            if (($header->rcode eq "NOERROR") && ($header->ancount > 0)) {
                                @anSec = $reply->answer;
                                foreach $rr (@anSec) {
                                    if ($rr->type eq 'TLSA') {
                                        return "TLSA,";
                                    }
                                }
                            }
                        }
                    }
            }
        } else {
            return "0,";
		}
	} else {
		return "na,";
	}
	
	return "0,";
}
	

