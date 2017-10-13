#!/usr/bin/perl
#tcpclient.pl

use IO::Socket::INET;

# flush after every write
$| = 1;

my ($socket,$client_socket);

# creating object interface of IO::Socket::INET modules which internally creates
# socket, bind and connects to the TCP server running on the specific port.
$socket = new IO::Socket::INET (
	PeerHost => '192.168.12.133',
	PeerPort => '5000',
	Proto => 'tcp',
) or die "ERROR in Socket Creation : $!\n";

print "TCP Connection Success.\n";

# read the socket data sent by server.
$data = <$socket>;
# we can also read from socket through recv() in IO::Socket::INET
# $socket->recv($data,1024);
print "Received from Server : $data\n";

# write on the socket to server.
$data = "DATA from Client";
print $socket "$data\n";
# we can also send the data through IO::Socket::INET modue,
# $socket->send($data);

sleep (10);
$socket->close();
