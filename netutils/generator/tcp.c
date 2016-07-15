#include "tcp.h"

int initTCP(struct Arguments *args)
{
	//struct sockaddr_in *dst_ip;
	int port;
	int sock;

	//dst_ip = resolve(args->target);

	port = args->port;

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		die ("socket failed");

	struct sockaddr_in servAddr;
	memset(&servAddr, 0, sizeof(servAddr)); // Zero out structure
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(port);
	//servAddr.sin_addr = (*dst_ip);


	int rtnVal = inet_pton(AF_INET, args->target, &servAddr.sin_addr.s_addr);
	if (rtnVal == 0)
		fatal ("inet_pton() failed", "invalid address string");
	else if (rtnVal < 0)
		die ("inet_pton() failed");

	if (connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
		die("connect() failed");

	return sock;
}

int loopTCP(struct Arguments *args, const int sock)
{
	uint8_t *data;

	data = allocate_ustrmem(IP_MAXPACKET);

	while (checkSignal())
	{
		randomPayload(data, args->length);

		ssize_t numBytes = send(sock, data, args->length, 0);
		if (numBytes < 0)
			die ("send() failed");
		else if (numBytes != args->length)
			fatal ("send()", "sent unexpected number of bytes");


		unsigned int totalBytesRcvd = 0; // Count of total bytes received
		fputs("Received: ", stdout);

		while (totalBytesRcvd < args->length) {
			char buffer[2000]; // I/O buffer

			numBytes = recv(sock, buffer, 2000 - 1, 0);
			if (numBytes < 0)
				die ("recv() failed");
			else if (numBytes == 0)
				fatal ("recv()", "connection closed prematurely");

			totalBytesRcvd += numBytes; // Keep tally of total bytes
			buffer[numBytes] = '\0';
			// Terminate the string!
			fputs(buffer, stdout);
			// Print the echo buffer
		}

		printf ("\n");

		sleep (args->frequency);
	}

	return 0;
}
