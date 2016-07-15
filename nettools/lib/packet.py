

def dumpPacket(pkt):
	l = len(pkt)
	
	for i in range(l):
		byte = ord(pkt[i])
		print "%02x " % (byte),

		if ((i % 16 == 15) or (i == l-1)):
			for j in range(15 - (i % 16)):
				print "   ",

			print "|",

			j = (i - (i %16))
			while (j <= i):
				byte = ord (pkt[j])
				if (( byte > 31) and (byte < 127)):
					print "%c" % (byte),
				else:
					print ".",

				j +=1

			print ""

	print ""
