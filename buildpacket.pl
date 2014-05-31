use Net::DNS;

if ( $#ARGV != 0 ) {
    print "Usage: perl buildpacket.pl <domain>\n";
    print " Example: perl buildpacket.pl 1x1.cz\n";
    print " Coded by Vypor, https://github.com/Vypor\n";
    exit(1);
}

my $domain = $ARGV[0];

my $dnspacket = new Net::DNS::Packet( $domain, 'IN', 'ANY' );
$dnspacket->header->qr(0);    #Query Responce Flag
$dnspacket->header->aa(0);    #Authoritative Flag
$dnspacket->header->tc(0);    #Truncated Flag
$dnspacket->header->ra(0);    #Recursion Desired
$dnspacket->header->rd(1);    #Recursion Available
$udp_max = $dnspacket->header->size(65527);    #Max Allowed Byte Size
my $dnsdata = $dnspacket->data;

open (FILE, ">>$domain.pkt");
print FILE $dnsdata;
close FILE;
