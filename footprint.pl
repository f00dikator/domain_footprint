#!/usr/bin/perl

#####################################################################
#  By John Lampe...j_lampe@bellsouth.net
#  
#  Usage: ./footprint.pl -C "company name" -D "domain.com"
#  Do, ./footprint.pl -h for different options
#
######################################################################
use Net::DNS;
use Socket;

$|=1;

$REZFILE = "Footprint.Rezults";
$whois_server = "whois.arin.net";
$dom_whois_server = "whois.networksolutions.com";
@email_address = ();
@dns_servers = ();
%dns_servers = ();
@contact_handles = ();
$dash = "-" x 20;

get_cli(); 
YewSage() if ($ash{-h});
open (OUT, ">$REZFILE") || die "Can't open Results File. $!\n";

if ($ash{-W}) {$whois_server = $ash{'-W'};}

if ($ash{'-C'}) {
    @cnames = split (/\,/, $ash{'-C'});
    foreach $companyname (@cnames) {
        print OUT $dash;
        print OUT "Results of whois \"$companyname\"\@$whois_server\n";
        $whois_company = mywhois($companyname, $whois_server);
        if ($whois_company =~ /No match for/) {
            my @alt_whois = split (/\s+/, $whois_company);
            foreach $alt (@alt_whois) {
                next unless ($alt =~ /[a-zA-Z]*\.[a-zA-Z]*\.[a-zA-Z]*\.]/);
                my $tmpwhois_server = $alt;
                print "Redirected to WHOIS SERVER $tmpwhois_server\n";
            }
            $whois_company = mywhois($companyname, $tmpwhois_server);
        }    
        print OUT "$whois_company\n\n\n\n";
        @tmprray = split (/\s+/, $whois_company);
        foreach $foo (@tmprray) {
            $fieldcount++;
            if ($tmprray[$fieldcount - 1] =~ /^\(/) {
                print "Getting ready to query $tmprray[$fieldcount] at $whois_server\n";
                $whois_netblk = mywhois($tmprray[$fieldcount], $whois_server);
                print OUT $dash;
                print OUT "Results of whois \"$tmprray[$fieldcount]\"\@$whois_server\n";
                print OUT "$whois_netblk\n\n\n\n";
                $ipstart = $tmprray[$fieldcount + 1];
                $ipend = $tmprray[$fieldcount + 3];
                print "Would you like to resolve the IP's within the range $ipstart to $ipend [n]\n";
                chop ($ans = <STDIN>);
                if (lc($ans) =~ /y/) {
                    reverse_resolve ($ipstart, $ipend);
                }
                $whois_netblk = "";
            }
        }
        if ($ash{'-c'}) {
            print "This feature doesn't work right now...maybe later\n";          #remove remove remove FIX FIX
            next;                                                                 #remove remove remove FIX FIX
            my $testing = crawl_sec($companyname);
            print OUT $dash;
            print OUT "Interesting results from www.sec.gov\n";
            find_10qk ($testing);   
            print OUT "\n\n\n\n";
       }
    }
}  



if ($ash{'-D'}) {
    @domains = split (/\,/, $ash{'-D'});
    print "@domains will be processed\n";                             
    $domainsprocessed = 1;
    foreach $dom (@domains) {
        my $site = "www" . "." . $dom;
        my $htmldoc = return_html ($site);
        my @hrefrray = find_href ($htmldoc);
        print OUT $dash;
        print OUT "Offsite links off of $site\n";
        foreach $h (@hrefrray) { print OUT "$h\n" if ($h =~ /http/); }
        $domflag = 1;
        $whois_domain = mywhois ($dom, $dom_whois_server);
        print OUT $dash;
        print OUT "Results of whois $dom\n";
        print OUT "$whois_domain\n\n\n\n";
        get_MX($dom);
        my @tmprray = split (/\s+/, $whois_domain);
        foreach $foo (@tmprray) {
            if ($foo =~ /\@/) { 
                $tmprray[$index - 1] =~ tr/[a-zA-Z0-9\-]//cd;
                push (@contact_handles, $tmprray[$index - 1]);    
                push (@email_address, $foo);
            }
            if ( ($foo =~ /[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/) && ($domflag) ) {
                push (@dns_servers, $dom);
                push (@dns_servers, $foo);
                $dns_servers{$dom} = \@dns_servers;
                $domflag = 0;
            }
            $index++;
        }
        $domainsprocessed++;
    }
} 


if ($ash{'-H'}) {
    while ( ($domain, $iprray) = each %dns_servers) {
        $find_HST = mywhois ($dns_servers{$domain}->[1],$whois_server);
        @tmprray = split (/\s+/, $find_HST);
        foreach $val (@tmprray) {
            $val =~ tr/[a-zA-Z0-9\-]//cd;
            if ($val =~ /-HST/) {
                $whois_hst = mywhois ("server $val",$whois_server);
                print OUT $dash;
                print OUT "Results of whois \"server $val\"\@$whois_server\n";
                print OUT "$whois_hst\n\n\n\n";
            }     
        }        
    }
}



foreach $dom (@domains) {  
    $contact_query = mywhois ("\@$dom", $whois_server);
    $contact_query .= mywhois ("\@$dom", $dom_whois_server);
    print OUT $dash;
    print OUT "Results of whois \"\@$dom\"\@$whois_server \@$dom_whois_server\n";
    print OUT "$contact_query\n\n\n\n";
    @tmprray = split (/\s+/, $contact_query);
    $index=0;
    foreach $foo (@tmprray) {
        if ($foo =~ /\@/) { 
            $tmprray[$index - 1] =~ tr/[a-zA-Z0-9\-]//cd;
            push (@contact_handles, $tmprray[$index - 1]);    
            push (@email_address, $foo);
        }
        $index++;
    }
}



foreach $contact (@email_address) {
        next if ($contact eq "");
        $term=1;
        foreach $foo (@contemp) {$term = 0 if ($contact eq $foo);}
        next if ($term == 0);
        $whois_contact = mywhois ($contact, $whois_server);
        $whois_contact = "" if ($whois_contact =~ /No match for/);
        $whois_contact .= mywhois ($contact, $dom_whois_server);
        next if ($whois_contact =~ /No match for/);
        print OUT $dash;
        print OUT "Results of whois \"$contact\"\@$whois_server \@$dom_whois_server\n";      
        print OUT "$whois_contact\n\n\n\n";
        push (@contemp, $contact);
        $flag=0;
}

print OUT $dash;
print OUT "Email Address List:\n";
foreach $contact (@email_address) {print OUT "$contact\n";}



foreach $contact (@contact_handles) {
        next if ($contact eq "");
        $whois_contact = mywhois ($contact, $whois_server);
        next if ($whois_contact =~ /No match for/);
        print OUT $dash;
        print OUT "Results of whois \"$contact\"\@$whois_server\n";      
        print OUT "$whois_contact\n\n\n\n";
        $flag=0;
}






while (($domain, $servarray) = each %dns_servers) {
    print "Would you like to attempt a zone transfer for $domain \= $dns_servers{$domain}->[1]\n";
    chop ($ans=<STDIN>);
    next if (lc($ans) !~ /y/);
    $ip = $dns_servers{$domain}->[1];
    zone_transfer($domain, $ip);            
}



print "Results are in $REZFILE\n";
exit(0);





##########################################################################################################
#     SUBROUTINES
###########################################################################################################






sub YewSage {
    print qq!
              Usage:  ./footprint.pl -C \"FULL_COMPANY NAME\" -D \"domain.\{net,com,edu}\,domain2" [-W Whois.server]
              -C :  Company name.  Can be multiples, ie -C "Company 1,Company 2,Company 3", etc...
              -D :  Domain(s).  Can be multiples, ie -D "sony.com,google.com,philly.com", etc...
              -h :  This message 
              -c :  Crawl www.sec.gov EDGAR DB looking for "subsidiary" regexp
              -H :  Search for DNS HST records and query for domain authority (if company maintains DNS)
              -W :  Specify a different whois server (default is whois.arin.net)
              Example: ./footprint.pl -C \"Georgia Pacific,Timber Company\" -D \"gapac.com\,gp.com" -W whois.ripe.net -H
    !;
    print "\n\n";
    exit(0);
}





sub get_cli {
    while (defined ($value = shift (@ARGV))) {
        ($value =~ /^-/) ? $temp = $value : $ash{$temp} = $value;
        ($value eq "-H") ? $ash{$temp} = "1" : 0;
        ($value eq "-c") ? $ash{$temp} = "1" : 0;
        ($value eq "-h") ? $ash{$temp} = "1" : 0;
    }
}        







sub reverse_resolve {
    print OUT $dash;
    print OUT "Results of reverse lookup of $_[0] to $_[1]\n";
    ($s1, $s2, $s3, $s4) = split (/\./, $_[0]);
    ($e1, $e2, $e3, $e4) = split (/\./, $_[1]);
    ($s4 > $e4) ? $flag4 = 1 : $flag4 = 0;  
    ($s3 > $e3) ? $flag3 = 1 : $flag3 = 0;
    ($s2 > $e2) ? $flag2 = 1 : $flag2 = 0;
    RESOLVE: while ( ($s1 <= $e1) && (($s2 <= $e2) || ($flag2)) && (($s3 <= $e3) || ($flag3)) && (($s4 <= $e4) || ($flag4)) ) {    
                  $srcaddr = $s1 . "." . $s2 . "." . $s3 . "." . $s4;
                  my $name = gethostbyaddr ( pack(C4, split (/\./, $srcaddr)),2);
                  print OUT "$srcaddr \= $name\n" unless ($name eq '');
                  $name = "";
                  $srcaddr = "";
                  if ($s4 == 255) {$s4 = 1; $s3++; next RESOLVE;}
                  if ($s3 == 255) {$s3 = 1; $s2++; next RESOLVE;}
                  if ($s2 == 255) {$s2 = 1; $s1++;}
                  $s4++;
    }

}







sub get_MX {
    $name = shift;
    print OUT $dash;
    print OUT "Results of MX search for $name\n";
    $res = new Net::DNS::Resolver;
    @mx = mx($res, $name);
    if (@mx) {
         foreach $rr (@mx) {
             print OUT $rr->preference, " ", $rr->exchange, "\n";
         }
    } 
}





sub zone_transfer {
    $domain = $_[0];
    $server = $_[1];
    print OUT $dash;
    print OUT "Rezults of Zone Transfer of $domain via server $server\n";
    $res = new Net::DNS::Resolver;
    $res->nameservers($server);
    @zone = $res->axfr($domain);
    foreach $rr (@zone) {
        print OUT "$rr\n";
        $rr->print;                                #remove?
    }
}




sub crawl_sec {
    my $company_name = $_[0];
    $company_name =~ tr/ /\+/;
    my $conlength = 83 + length($company_name);
    my ($remote,$port, $iaddr, $piaddr, $proto, $ret, $tmp, $bytes_read);
    $remote = "204.192.28.14";
    my $string = "POST \/cgi-bin\/formlynx.pl.b HTTP\/1.1\r\n" .
                 "Accept: application\/msword, image\/gif, image\/x-xbitmap, imapge\/jpeg, image\/pjpeg, \*/\*\r\n" .
                 "Referer: http:\/\/www.sec.gov\/edgar\/searchedgar\/formpick.htm\r\n" .
                 "Accept-Language: en-us\r\n" .
                 "Content-Type: application\/x-www-form-urlencoded\r\n" .
                 "Accept-Encoding: gzip, deflate\r\n" .
                 "User-Agent: Mozilla\/4.0 \(compatinble\; MSIE 5.01 Windows NT 5.0\)\r\n" .
                 "Host: www.sec.gov\r\n" .
                 "Content-Length: $conlength\r\n" .
                 "Connection: Keep-Alive\r\n\r\n" .
                 "Form-Pick-List\=ALL\&form\=\&company=" .
                 $company_name .
                 "\&date-range\=Entire+Database+\%28since\+1\%2F1\%2F94\%29\r\n\r\n";

    $port = 80;
    if ($port =~ /\D/) { $port = getservbyname($port, 'tcp') }
    die "No port" unless $port;
    $iaddr   = inet_aton($remote);
    $piaddr   = sockaddr_in($port, $iaddr);
    $proto   = getprotobyname('tcp');
    socket(SOCK, PF_INET, SOCK_STREAM, $proto)  || die "damn! no socket: $!";
    select (SOCK);
    connect(SOCK, $piaddr) || die "damn! no connect: $!";
    print $string;
    while (($bytes_read = read(SOCK, $tmp, 1024)) > 0) {
        $ret .= $tmp;
        $tmp = "";
    }
    select(STDOUT);
    close (SOCK) || die "damn: $!";
    return ($ret);
}




sub mywhois {
    my ($ret, $remote,$tmp, $port, $bytes_read, $iaddr, $piaddr, $proto);
    $remote = $_[1];
    print " \$remote is $remote\n";                              #remove remove
    my $string = $_[0];
    $port = 43;
    if ($port =~ /\D/) { $port = getservbyname($port, 'tcp') }
    die "No port" unless $port;
    $iaddr   = inet_aton($remote)  || die "Dead in mywhois. $!\n";
    $piaddr   = sockaddr_in($port, $iaddr);
    $proto   = getprotobyname('tcp');
    socket(SOCK, PF_INET, SOCK_STREAM, $proto)  || die "socket: $!";
    connect(SOCK, $piaddr) || die "connect: $!";
    select (SOCK);
    $|=1;
    print "$string\n";
    while (($bytes_read = read(SOCK, $tmp, 1024)) > 0) {
       $ret .= $tmp;
       $tmp = "";
    }
    select(STDOUT);
    close (SOCK) || die "close: $!";
    return ($ret);
}




sub find_href {
    my $string = shift;
    my $patt = "href";
    my @rray = split (/\s+/, $string);
    foreach $value (@rray) {
        if ($value =~ /$patt/) {
            ($not, $value, $snot) = split (/\"/, $value);
            $value =~ tr/[a-zA-Z0-9\/\-\.]//cd;
            push (@retrray, $value);
        }
    }
    return (@retrray);
}
    

 


sub find_10qk {
    my $string = shift;
    my @tmprray = split (/\n/, $string);
    my (@retrray);
    foreach $line (@tmprray) {
        next unless ($line =~ /10\-K|10\-Q/);
        my @tmprray2 = split (/\s+/, $line);
        foreach $value (@tmprray2) {
            my @links = find_href($value);               
            my $substring = $links[0];
            next if ($substring eq "");
            my $page = return_html($substring);
            my $retvalue = find_subsidiary($page);
            print OUT "$retvalue\n\n";
        }
    }
}





sub find_subsidiary {
    my $page = shift;
    my ($i,$ret,$j,$tmp);
    my @rray = split (/\s+/, $page);
IBLOCK:    for ($i=0; $i < $#rray; $i++) {
        if (lc($rray[$i]) =~ /subsidiary/) {
            next IBLOCK if ($i < 50);
            for ($j= $i - 25; $j < ($i + 25); $j++) {
                $tmp = $tmp . $rray[$j] . " ";
            }
            $ret .= $tmp;
        }
    }   # END IBLOCK
    $ret .= "\n\n";
    return ($ret);
}




sub return_html {
    my $link = shift;
    my ($remote,$port, $iaddr, $piaddr, $proto, $ret, $tmp, $bytes_read);
    my @rem = (gethostbyname($link))[4];
    ($a,$b,$c,$d) = unpack ('C4', $rem[0]);
    $remote = $a . "." . $b . "." . $c . "." . $d;
    my $string = "GET / HTTP/1.0\r\n\r\n";
    $port = 80;
    if ($port =~ /\D/) { $port = getservbyname($port, 'tcp') }
    die "No port" unless $port;
    $iaddr   = inet_aton($remote) || return(0);
    $piaddr   = sockaddr_in($port, $iaddr);
    $proto   = getprotobyname('tcp');
    socket(MYSOCK, PF_INET, SOCK_STREAM, $proto)  || return(0);
    select (MYSOCK);
    connect(MYSOCK, $piaddr) || return(0);
    print "$string";
    while (($bytes_read = read(SOCK, $tmp, 1024)) > 0) {
        $ret .= $tmp;
        $tmp = "";
    }
    select(STDOUT);
    close (MYSOCK) || return(0);
    return ($ret);
}

