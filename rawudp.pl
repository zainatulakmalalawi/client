use strict;
use Socket;

my $ip_src = (gethostbyname($ARGV[0]))[4];
my $ip_dst = (gethostbyname($ARGV[1]))[4];

if (!defined $ip_src or !defined $ip_dst) {
	exit "Usage: $0 <source ip> <destination ip>\n";
}

socket(RAW, AF_INET, SOCK_RAW, 255) or die $!;
setsockopt(RAW, 0, 1, 1);

main();

sub main {
	my $packet;

	$packet = ip_header();
	$packet .= udp_header();

	$packet .= payload();

	send_packet($packet);
}

sub ip_header {
	my $ip_ver = 4;
	my $ip_header_len = 5;
	my $ip_tos = 0;
	my $ip_total_len = $ip_header_len + 20;
	my $ip_frag_id = 0;
	my $ip_frag_flag = '000';
	my $ip_frag_offset = '0000000000000';
	my $ip_ttl = 255;
	my $ip_proto = 17;
	my $ip_checksum = 0;

	my $ip_header = pack (
		'H2 H2 n n B16 h2 c n a4 a4',
		$ip_ver.$ip_header_len, $ip_tos, $ip_total_len,
		$ip_frag_id, $ip_frag_flag.$ip_frag_offset,
		$ip_ttl, $ip_proto, $ip_checksum,
		$ip_src,
		$ip_dst
	);

	return $ip_header;
}

sub udp_header {
	my $udp_src_port = 60;
	my $udp_dst_port = 60;
	my $udp_len = 8 + length(payload());
	my $udp_checksum = 0;

	my $udp_header = pack (
		'n n n n', 
		$udp_src_port, $udp_dst_port, 
		$udp_len, $udp_checksum
	);

	return $udp_header;
}

sub payload {
	my $data = 'abcdefghijklmnopqrstuvwxyz hi';

	my $payload = pack ('a'.length($data), $data);

	return $payload;
}
	
sub send_packet {
	send (RAW, $_[0], 0, pack('Sna4x8', AF_INET, 60, $ip_dst));
}

sub checksum {}
