#!/usr/bin/python
import socket
import select
import sys, os
import errno
import argparse

from lib import net
from lib import screen
from lib import signalHandler
from lib import tcp
from lib import connection


def printStats():

	global max_clients

	screen.clearSession (max_clients, len(clients))
	
	if (len(clients) == 0): max_clients=-1

	for c in clients:
		c_rx = net.calcByte(stats[c][1])
		c_tx = net.calcByte(stats[c][2])
		r_rx = net.calcByte(stats[c][3])
		r_tx = net.calcByte(stats[c][4])

		m = "%s [%s/%s] (%s" % (net.peerSockName(c), c_rx, c_tx, net.localSockName(c))
		
		t = cons.lookup(c)
		if (t!=c):

			m = m + "|%s) [%s/%s] %s" % (net.localSockName(t), r_rx, r_tx, net.peerSockName(t))
		else:
			m = m + "|loopback)"

		screen.session (m)
	
	max_clients = len(clients)

def netproxy (args):

	screen.info ("Enea network proxy")

	global max_clients
	max_clients = -1

	global cons
	cons = connection.Connection()
	interface = args.s
	port = args.l
	target = (args.t, args.p)

	srvSock = tcp.serverSocket ((interface, port))


	ln = "-" * 30
	m = "Sessions:\n" + ln

	screen.info (m)
	

	global stats
	stats = {}

	rfds = []
	global clients
	clients = []
	rSet = wSet = eSet = []


	while (signalHandler.checkSignal()):

		rfds = [srvSock] + cons.keys()

		try:
			rSet, wSet, eSet = select.select (rfds, [], [])
			
			for r in rSet:

				if (r == srvSock):
					t = tcp.clientSocket(srvSock, args)
					clients.append(t)
					stats[t] = ["open", 0, 0, 0,0]
					cons.create (t)
				elif r in clients:
					handleClient (r, args)
				else:
					handleSession (r, args)

			printStats()

		except select.error as e:
			if e[0] != errno.EINTR: raise
			else: break



def handleSession (sock, args):

	code, data = tcp.socketHandler (sock, 100)
	
	if code == 0:
		t = cons.lookup(sock)
		# update stats
		t.sendall (data)	
		stats[t][3] += len(data)
		stats[t][2] += len(data)
	else:
		t = cons.lookup(sock)
		stats[t][3] = 0
		stats[t][4] = 0
		cons.delete (sock)
		tcp.closeSocket (sock)


def handleClient (sock, args):

	target = (args.t, args.p)

	code, data = tcp.socketHandler (sock, 100)

	if code == 0:
		
		if cons.empty(sock):
			if (target[0] != None):
				dst = tcp.remoteSocket (target, args)
				if (dst != -1): cons.add (sock, dst) # print error maybe
			else:
				cons.add (sock, sock)
		
		t = cons.lookup (sock)

		# update stats
		t.sendall (data)
		if (t == sock):
			stats[sock][1] += len(data)
			stats[sock][2] += len(data)
		else:	
			stats[sock][1] += len(data)
			stats[sock][4] += len(data)
	else:
		del stats[sock]
		t = cons.lookup (sock)
		clients.remove (sock)
		cons.clear (sock)
		tcp.closeSocket (t)
		tcp.closeSocket (sock)


def main (argv):
	parser = argparse.ArgumentParser (description='network proxy')
	
	parser.add_argument ('-t', metavar = 'Target', help='Target to send traffic')
	parser.add_argument ('-p', metavar = 'Port', type=int, help='TCP Port')
	parser.add_argument ('-s', metavar = 'Source', default='0.0.0.0', help='Listening interface')
	parser.add_argument ('-l', metavar = 'Listen', type=int, help='TCP listening port')
	args = parser.parse_args()
	signalHandler.initSignal()

	netproxy (args)
	
if __name__ ==  '__main__':
	sys.exit (main(sys.argv))

