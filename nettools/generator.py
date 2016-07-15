#!/usr/bin/python
import socket
import select
import sys, os
import errno
import random
import string
import argparse

from lib import net
from lib import screen
from lib import signalHandler
from lib import tcp

def printStats(args):
	
	global max_clients
	
	screen.clearSession (max_clients, len(clients))

	if (len(clients) == 0): max_clients =-1

	
	for c in clients:
		rx = stats[c][1]
		tx = stats[c][2]
		m = net.localSockName(c) + " <--> "+ net.peerSockName(c) + " "
		
		m = m + "[" + net.calcByte(rx) + "/" + net.calcByte(tx) + "]"
		screen.session (m)

	max_clients = len(clients)


def generator (args):

	screen.info ("Enea packet generator")

	global max_clients
	max_clients = -1

	global clients
	clients = []

	global stats
	stats = {}


	screen.info ("Sessions\n---------------------------------------")

	for i in range(args.c):
		rs = tcp.remoteSocket ((args.t, args.p), args)
		if (rs == -1):
			screen.info ("Connection failed to " + args.t + ":" + str(args.p))
			return 
		else:
			clients.append (rs)
			stats[rs] = ["open", 0,0]
			#screen.info ("Sessions\n-----------------------------------------------------------------------")
			printStats(args)
			#screen.info ("Sessions\n-----------------------------------------------------------------------")


	rfds = []
	rSet = wSet = eSet = []

	while (signalHandler.checkSignal()):

		rfds = clients

		try:
			rSet, wSet, eSet = select.select (rfds, [], [], args.f)
			
			for r in rSet:
				if r in clients:
					handleClient (r, args)

			if rSet == []:
				for t in clients:
					tcpGenerator (t, args)
		
			printStats (args)
			if clients == []: return

		except select.error as e:
			if e[0] != errno.EINTR: raise
			else: break

def tcpGenerator (sock, args):
	size = args.l
	txt = randomword (size)
	stats[sock][2] += size
	sock.sendall (txt)
	#app.info (net.localSockName (sock) + " => " + net.peerSockName (sock) + " : " + str(len(txt)) + " bytes")

def randomword (length):
	return ''.join (random.choice (string.lowercase) for i in range(length))

def handleClient (sock, args):

	try:
		msg = sock.recv (100)

		if (len(msg) == 0):
			clients.remove(sock)
			tcp.closeSocket (sock)
			return

		stats[sock][1] += len(msg)

	except socket.error as e:
		screen.info (net.localSockName(t) + ": " + e.strerror)


def main (argv):

	parser = argparse.ArgumentParser (description='Generate packets')
	parser.add_argument ('proto', help='Traffic protocol')
	parser.add_argument ('-t', metavar = 'Target', default='127.0.0.1', help='Target to send traffic')
	parser.add_argument ('-p', metavar = 'Port', type=int, default=10000, help='TCP Port (default 10000)')
	parser.add_argument ('-l', metavar = 'Length', type=int, default=100, help='Payload size (default 100)') 
	parser.add_argument ('-c', metavar = 'Connections', type=int, default=10, help='Number of connections (default 10)')
	parser.add_argument ('-f', metavar = 'Frequency', type=int, default=1, help='Frequency (default 1)')
	args = parser.parse_args()

	signalHandler.initSignal()

	generator (args)

if __name__ ==  '__main__':
	sys.exit (main(sys.argv))
	



