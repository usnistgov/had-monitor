# had-monitor
# NIST Software Disclaimer #

NIST-developed software is provided by NIST as a public service. You
 may use, copy and distribute copies of the software in any medium,
 provided that you keep intact this entire notice. You may improve,
 modify and create derivative works of the software or any portion of
 the software, and you may copy and distribute such modifications or
 works. Modified works should carry a notice stating that you changed
 the software and should note the date and nature of any such
 change. Please explicitly acknowledge the National Institute of
 Standards and Technology as the source of the software.

NIST-developed software is expressly provided “AS IS.” NIST MAKES NO
WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT OR ARISING BY
OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT
AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE
OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT
ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY
REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS
THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY,
RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

You are solely responsible for determining the appropriateness of
using and distributing the software and you assume all risks
associated with its use, including but not limited to the risks and
costs of program errors, compliance with applicable laws, damage to or
loss of data, programs or equipment, and the unavailability or
interruption of operation. This software is not intended to be used in
any situation where a failure could cause risk of injury or damage to
property. The software developed by NIST employees is not subject to
copyright protection within the United States.

<p>
Three perl scripts used to perform the tests of the High Assurance Domain (HAD)
Monitor: https://www.had-pilot.com/had-monitor.html

Requirements:

perl modules:<br>
    Net::DNS<br>
    Net::DNS::SEC<br>
    Net::DNS::Resolver<br>
    Time::Local
    Getopt::Long
    LWP::UserAgent
    LWP::Protocol::https
    
A DNSSEC-validating resolver is also needed for the tests.  The scripts send DNS queries through the
host's lcoal resolver, but sets the DNSSEC-OK (DO) bit.

Gneral input
<p>
The input for all the scripts are the same, with different fields used and different files output.  
The general format is:
</p>
<p>
domain.name,test?,org name,family,URL,DNSSEC,validity-status,algo,SPF,DKIM,DMARC,TLSA,STARTTLS,http,https,TLSA
</p>
<p>
The first field is a zone name (i.e. dnsops.gov), second is a flag for the script to test/not test.  Third and
fouth is the org/enterprise name (i.e. Dept. of Commerce) and the group (used to designate familes of tests). 
Fifth field is is the URL for the homepage, usually in the form of http://www.domain.name/.  The remaining 
fields are the test results by the three scripts.
</p>

Individual scripts:
1. had-mon-dns.pl
<p>
Used to perform the DNSSEC checks.  The tests are:
</p>
DNSSEC deployed? (1=Yes, 0=No)
DNSSEC Valid? (V=valid, I=island, or B=bogus)
DNSSEC algorithm (algorithm code, or 0 if no DNSSEC)

2. had-mon-email.pl
<p>
Used to perform tests for email security.  This script only looks for DNS artifacts currently and relies on 
another way to populate the test results for STARTTLS.  The tests are:
</p>
SPF found? (1=Yes, 0=No, NS=Yes and appears to just be "-all")
DKIM found? (?=No, else the selector string) - note that this is not a test, but copied from other tests or results
DMARC found? (1=Yes, 0=No)
TLSA RR for SMTP servers? (1=Yes, 0=No, NA=No servers found)
STARTTLS? (1=Yes, 0=No, NA=no mail servers found)

3. had-mon-web.pl
<p>
Used to perform web server tests.  They are:
</p>
HTTP server found? (1=Yes, 0=No)
HTTPS available? (1=Yes, 0=No)
HTTPS certificate found in TLSA RR? (1=Yes, 0=No)
<p>
How the results are compiled and interpreted is not covered in this package.  It is up to the individual user.
</p>  
