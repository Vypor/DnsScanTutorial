use strict;
use warnings;
use Net::Pcap;
use Net::Pcap::Easy;

if ( $#ARGV != 2 ) {
    print "Usage: perl filter.pl <outputfile> <minbytereply> <domain>\n";
    print " Example: perl filter.pl output.txt 3000 1x1.cz\n";
    print " Coded by Vypor, https://github.com/Vypor\n";
    exit(1);
}

my $err;
my $minbytes = $ARGV[1];
my $domain = $ARGV[2];

my $interface = pcap_lookupdev( \$err );
my $ethip = `/sbin/ifconfig $interface | grep "inet addr" | awk -F: '{print \$2}' | awk '{print \$1}'`;
$ethip = substr( $ethip, 0, -1 );

# all arguments to new are optoinal
my $npe = Net::Pcap::Easy->new(
    dev              => $interface,
    filter           => "not src host $ethip and port 53 and greater $minbytes",
    packets_per_loop => 10,
    bytes_to_capture => 1024,
    timeout_in_ms    => 0, # 0ms means forever
    promiscuous      => 0, # true or false

        udp_callback => sub {
        my ($npe, $ether, $ip, $udp, $header ) = @_;
        my $xmit = `date +"%H:%M:%S"`;
        chomp($xmit);
        print "$xmit $ip->{src_ip} -> $ip->{dest_ip} $udp->{len}\n";

        open (FFILE, ">>$ARGV[0]");
        print FFILE "$ip->{src_ip} $domain $udp->{len}\n";
        close FFILE;
},
);

1 while $npe->loop;
