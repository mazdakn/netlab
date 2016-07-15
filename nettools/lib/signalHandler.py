import signal
import screen

# make it a class 

def signalHandler (signal, frame):
	signalFlag = False
	screen.info ("Ctrl+C pressed")

def initSignal():
	global signalFlag 
	signalFlag = True
	signal.signal (signal.SIGINT, signalHandler)

def checkSignal ():
	return signalFlag
