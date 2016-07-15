import socket 

import screen
import net

def serverSocket (address):
	srvSock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
	srvSock.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	srvSock.bind (address)
	srvSock.listen (5) # fix 
	screen.info ("listening at " + net.localSockName(srvSock))
	return srvSock

def clientSocket (sock, args):
	sc, sockname = sock.accept()
	#screen.info (net.peerSockName(sc) + ' connected', args.curses)
	return sc

def remoteSocket (address, args):
	try:
		rs = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
		rs.connect (address)
		return rs #exception
	except socket.error as e:
		return -1

def closeSocket (sock):
	# better way to keep addreess
	# screen.info (net.localSockName(sock) + " closed", 2, 0) # maybe more
	sock.close()

def socketHandler (sock, chunk):
	try:
		msg = sock.recv(chunk)

		if (len(msg) == 0):
			return -1, None

		return 0, msg
	except socket.error as e:
		screen.info (e.strerror)
		return -1, None
