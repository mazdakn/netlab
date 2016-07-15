#!/usr/bin/python

import sys
import argparse
import socket
import errno
from struct import *
import ctypes

from lib import net
from lib import ethernet
from lib import signalHandler
from lib import screen
from lib import packet

class ifreq(ctypes.Structure):
	_fields_ = [("ifr_ifrn", ctypes.c_char * 16), ("ifr_flags", ctypes.c_short)]

class FLAGS(object):
	# linux/if_ether.h
	ETH_P_ALL	= 0x0003
	ETH_P_IP	= 0x0800
	# linux/if.h
	IFF_PROMISC	= 0x100
	#linux/sockios.h
	SIOCGIFFLAGS = 0x8913
	SIOCSIFFLAGS = 0x8914

def promisc (sock, iface, on):
	
	import fcntl
	ifr = ifreq()
	ifr.ifr_ifrn = iface
	fcntl.ioctl (sock, FLAGS.SIOCGIFFLAGS, ifr)

	if (on == True):
		ifr.ifr_flags |= FLAGS.IFF_PROMISC
	else:
		ifr.ifr_flags ^= FLAGS.IFF_PROMISC

	fcntl.ioctl (sock, FLAGS.SIOCSIFFLAGS, ifr)


def decodeEther (pkt):

	stats['ether'] += 1

	eth_len = 14
	eth_hdr = pkt[:eth_len]
	eth = unpack ('!6s6sH', eth_hdr)
	proto = socket.ntohs (eth[2])
	print ethernet.eth_addr(pkt[0:6]) + "->" + ethernet.eth_addr(pkt[6:12]),

	if proto != 8: # not IP
		print "proto: " + str(proto)
		return

	stats['ip'] += 1
	ip_hdr = pkt[eth_len:20+eth_len]

	iph = unpack ('!BBHHHBBH4s4s', ip_hdr)
	
	ver_ihl = iph[0]
	ver = ver_ihl >> 4
	ihl = ver_ihl & 0xF
	iph_len = ihl * 4

	ip_proto = iph[6]
	s_addr = str(socket.inet_ntoa (iph[8]))
	d_addr = str(socket.inet_ntoa (iph[9]))

	#print "IP(%s->%s)" % (str(s_addr),  str(d_addr)),

	if (ip_proto == 1):
		stats['icmp'] += 1
		u = iph_len + eth_len 
		icmp_hdr = pkt[u:u+4]

		icmph = unpack ('!BBH', icmp_hdr)

		icmp_type = icmph[0]
		code = icmph[1]
		chksum = icmph[2]

		print "ICMP(%s->%s type:%d code:%d)" % (s_addr, d_addr, icmp_type, code)
		return

	if (ip_proto == 17):
		stats['udp'] += 1

		u = iph_len + eth_len
		udp_hdr = pkt[u:u+8]

		udph = unpack ('!HHHH', udp_hdr)
		src_port = udph[0]
		dst_port = udph[1]
		chksum = udph[3]

		print "UDP(%s:%d->%s:%d)" % (s_addr, src_port, d_addr, dst_port)
		return 

	if (ip_proto == 6): # tcp
		stats['tcp'] += 1

		u = iph_len + eth_len
		tcp_hdr = pkt[u:u+20]

		tcph = unpack ("!HHLLBBHHH", tcp_hdr)

		src_port = tcph[0]
		dst_port = tcph[1]

		print "TCP(%s:%d->%s:%d)" % (s_addr, src_port, d_addr, dst_port)
		return

	print "IP(%s->%s : Proto %d)" % (s_addr, d_addr, ip_proto) 	


def decode(pkt, args):

	stats['pkts'] += 1
	iface = pkt[1][0]
	data = pkt[0]
	print iface + "(" + str(len (data)) + "B)",
	decodeEther (data)
	
	if (args.x):
		packet.dumpPacket (data)


def sniffer (args):

	global stats
	stats = {}
	stats['pkts'] = 0
	stats['ether'] = 0
	stats['ip'] = 0
	stats['icmp'] = 0
	stats['tcp'] = 0
	stats['udp'] = 0

	try:
		sock = socket.socket (socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(FLAGS.ETH_P_ALL))
	except socket.error ,msg:
		screen.info ("socket error: "+ str(msg))
		sys.exit()

	if (args.i != "any"):
		
		try:
			sock.bind((args.i,0))
	
		except socket.error ,msg:
			screen.info ("Socket error: " + str(msg))
			sys.exit()

		if (args.p):
			promisc (sock, args.i, True)

	while(signalHandler.checkSignal()):

		try:
			pkt = sock.recvfrom(1000)
			decode(pkt, args)
		except socket.error as e:
			if e[0] != errno.EINTR: raise
			else: break

	if ((args.i != "any") and (args.p == True)):
		promisc (sock, args.i, False)

def main(argv):

	parser = argparse.ArgumentParser (description = 'Enea Sniffer')
	parser.add_argument ("-i", metavar="Interface", default = "any", help= "Interface to sniffe (any or ..)")
	parser.add_argument ("-p", action = 'store_true', help="Enable promiscuous mode")
	parser.add_argument ("-x", action = 'store_true', help="Show raw packet")
	args = parser.parse_args()

	signalHandler.initSignal()
	sniffer(args)

	m = "All: %d  Ethernet: %d  IP: %d  ICMP: %d  TCP: %d  UDP: %d" % (stats["pkts"], stats["ether"], stats["ip"], stats["icmp"], stats["tcp"], stats["udp"])
	screen.info (m)


if __name__=='__main__':
	sys.exit(main(sys.argv))
