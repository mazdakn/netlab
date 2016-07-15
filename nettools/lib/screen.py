import curses
import sys

def info (msg):
	print "[*] " + msg

def session (msg, output=None):
	print msg

def fatal (msg):
	print "[-] " + msg

def clearSession(nlines, nclients):
	
	if (nlines == -1):
		return

	for c in range(nlines):
		sys.stdout.write("\033[F")
		sys.stdout.write("\033[K")

	if nclients == 0: 
		print ""
		sys.stdout.write("\033[F")
		sys.stdout.write("\033[K")

