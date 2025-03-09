#include "main.h"

int main (int argc, char **argv) {

	struct Arguments args;
	int udpSocket;

	// parse arguments
	if (parseArguments (argc, argv, &args))
		exit(EXIT_FAILURE);

	udpSocket = createUDPSocket (&args); // create udp socket
	transmit (udpSocket, &args); // trasmit packets
	closeUDPSocket (udpSocket); // close socket
	
	exit (EXIT_SUCCESS);
}
