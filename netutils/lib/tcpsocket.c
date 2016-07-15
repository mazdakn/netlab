#include "tcpsocket.h"

int serverSocket (const int port)
{
    int sock;
	struct sockaddr_in servAddr;

	if ((sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		die ("Socket failed");

	memset (&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr*) &servAddr, sizeof(servAddr)) < 0)
		die("bind failed");

	if (listen(sock, 5) < 0)
		die ("listen failed");

	return sock;
}


int clientSocket (struct sockaddr_in *srvAddr)
{
    int sock;

	if ((sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		die ("socket failed");

	if (connect (sock, (struct sockaddr *) srvAddr, sizeof(struct sockaddr_in)) < 0)
		die ("connect failed");

	return sock;
}


int connectSocket(const int srvSock)
{
	struct sockaddr_in clntAddr;
    char clntName[INET_ADDRSTRLEN];
	socklen_t addrLen = sizeof(struct sockaddr_in);
	
	int clntSock = accept (srvSock, (struct sockaddr *) &clntAddr, &addrLen);
	if (clntSock < 0)
		die ("accept failed");

	if (inet_ntop(AF_INET, &(clntAddr.sin_addr.s_addr), clntName, sizeof(clntName)) != NULL) {
		char msg[100]; // constant
		sprintf(msg, "Connection from %s:%d", clntName, ntohs(clntAddr.sin_port));
		info (msg);
	}
	else
		info ("Unable to get client address"); // need to be changed

	return clntSock;
}

int readSock (const int sock, char *data, const int len)
{
    size_t numBytes = recv (sock, data, len, 0); 

	if (numBytes < 0)
		die ("recv failed");
				    
	if (numBytes < 0)
		fatal ("recv", "connection closed prematurely");
    
	return numBytes;
}

int sendSock (const int sock, char  *data, const int len)
{
	size_t numBytes = send(sock, data, len, 0);

	if (numBytes < 0)
		die ("send() failed");

	if (numBytes != len)
		fatal ("send()", "sent unexpected number of bytes");

	return numBytes;
}


int forwardToSocket (const int srcSock, const int dstSock)
{
	char buffer[2000]; // make it a constant

	int rxBytes = readSock (srcSock, buffer, 2000);
	
	int txBytes = sendSock (dstSock, buffer, rxBytes);

	printInfo (srcSock, rxBytes, txBytes);
	return txBytes;
}


int forwardToSocketLoop (const int srcSock, const int dstSock)
{
	char buffer[2000]; // buffer size, a constant
	int rxBytes = 1;
	int txBytes;

	while ((rxBytes > 0) && (checkSignal())) {
		rxBytes = readSock (srcSock, buffer, 2000);
		txBytes = sendSock (dstSock, buffer, rxBytes);
		printInfo (srcSock, rxBytes, txBytes);
		// checks
	}

	return 0;
}

int nonBlockingSocket (const int sock)
{
	if (fcntl (sock, F_SETOWN, getpid()) < 0)
		fatal ("Unale to set process owner", strerror (errno));

	if (fcntl (sock, F_SETFL, O_NONBLOCK | FASYNC) < 0)
		fatal ("Uname to put clinet into non-blocking/async mode", strerror (errno));

	return 1;
}
