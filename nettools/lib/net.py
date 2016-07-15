
def localSockName (sock):
	s = sock.getsockname()
	return s[0] + ":" + str(s[1])

def peerSockName (sock):
	try:
		s = sock.getpeername ()
		return s[0] + ":" + str(s[1])
	except socket.error as e:
		return "disconnected"

def getSockInfo (sock):
	return (localSockName(sock) + " <--> " + peerSockName (sock))


def calcByte (value):
    
	if value < 1000:
		return str(value) + "B"
			    
	value = value / 1000
	if value  < 1000:
		return str(value) + "KB"
								    
	value = value / 1000
	if value < 1000:
		return str(value) + "MB"

	value = value / 1000
	if value < 1000:
		return str(value) + "GB"
	
	value = value / 1000
	if value < 1000:
	    return str(value) + "TB"
	
	return "NA"
