#include "udpsocket.h"

// create udp socket, and connect to server
int createUDPSocket (struct Arguments *args)
{
	struct sockaddr_in server;
	int fd; 

	// create udp socket
	if ((fd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		fatal ("Socket:");

	// prepare server information
	server.sin_family = AF_INET;
	server.sin_port = htons (args->port);
	if (inet_pton (AF_INET, args->address, &(server.sin_addr)) != 1)
		error ("Invalid ip address");

	// connect to server, and use send 
	if (connect (fd, (struct sockaddr *)&server, sizeof(server)) == -1)
		fatal ("Connect:");

	return fd;
}


// close udp socket
void closeUDPSocket (int fd)
{
	close (fd);
}


// create specified packet
char *createPacket (uint32_t counter)
{
    char *packet; // pointer to packet
    struct Header hdr; // packet header
    char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz?*!@#$%^*&()"; // set for rand data

    if ((packet = malloc (PACKET_SIZE)) == NULL) // allocate memeory for packet
        fatal ("malloc:");

    hdr.pkt_cnt = htonl(counter); // field 1: counter
    hdr.pkt_token = htons(PACKET_TOKEN); // field 2: token

	/* 	two lease significant bit = 1
		rest of bits are 0 except bit 3, so flag is 0000 X011
		X = lease significant bit of counter:
			counter == odd  => X = 1 and flag1 = 0000 1011 = 11
			counter == even => X = 0 and flag1 = 0000 0011 = 3
	*/
    if (counter % 2 == 0) 
        hdr.pkt_flag1 = 3; // 0000 0011
    else 
        hdr.pkt_flag1 = 11; //0000 1011

    hdr.pkt_flag2 = ~(hdr.pkt_flag1); // flag2 = ~flag1

	// copy header to packet
    memcpy (packet, (char *)&hdr, HEADER_SIZE);

	// fill the rest of packet (payload) with random data
    for (int i = HEADER_SIZE; i< PACKET_SIZE; i++)
        packet[i] = charset[ rand() %  (sizeof(charset)-1)];

    return packet; // return pointer ot packet
}

// transmit data to server
void transmit (int udpSocket, struct Arguments *args)
{
	char *packet;
	uint32_t bucketToken = 0 ; // packet to send to speed
	uint32_t txThisRound = 0 ; // number of bytes sent each time slot
	uint64_t txTotal = 0; // total byte sent
	uint32_t pktTotal = 0; // total packets sent
	uint32_t tx; // data sent by each send()
	int32_t bucket = 0;

	time_t start, end; // measure transmission time
	uint32_t idealTime = DEFAULT_IDEALTIME; // time to sleep

	bucketToken = (args->speed) * 1000 / 8 / MSEC_FACTOR; // token per msec

	start = time(NULL); // save start of transmission time
 	while ( pktTotal < (args->packets))
 	{
		// transmit process for this time slot

		// zero vars
		txThisRound = 0;
		bucket = bucket + idealTime *  bucketToken; // add token to bucket

		// send until bucket is about to empty
		while ((bucket - PACKET_SIZE) > 0)
		{
			packet = createPacket (pktTotal); // create packet
			tx = send (udpSocket, packet, PACKET_SIZE, 0); // send to server
			if (tx < 0)
				continue; // if error in sending continue and try again

			// on send success
			txThisRound += tx; // bytes sent this time slot
			pktTotal++; // total packets sent
			bucket -= tx;
			
			if (pktTotal >= args->packets) break; // break if packets are sent
		}
		txTotal += txThisRound; // total bytes sent

		usleep(idealTime * MSEC_FACTOR); // sleep
 	}
	end = time(NULL);

	printf ("Total packets %u\t Total bytes %ld Time %ld Speed %ldKbps\n", pktTotal, txTotal, end - start, txTotal * 8 / (end - start) / 1000);
}
