#include "netutils.h"

void printBuffer (char *buffer, const int len)
{
	// memoery access
    buffer[len] = '\0';
	printf ("%s\n", buffer);
	fflush (stdout);
}

int tuple (struct sockaddr_in *addr, const char *server, int port)
{
	memset(addr, 0, sizeof(struct sockaddr_in)); // Zero out structure
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);

	int rtnVal = inet_pton(AF_INET, server, &(addr->sin_addr.s_addr));
	if (rtnVal == 0)
		fatal ("inet_pton() failed", "invalid address string");
	else if (rtnVal < 0)
		die ("inet_pton() failed");

	// address??
	return 0;
}

struct sockaddr_in *resolve (const char *target)
{
    struct addrinfo hints, *res;
	struct sockaddr_in *ipv4;
	int status;

	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	//Resolve target using getaddrinfo().
	if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0)
		fatal ("Address info failed", gai_strerror(status));

	ipv4 = (struct sockaddr_in *) res->ai_addr;
	freeaddrinfo (res);

	return ipv4;
}

void printInfo (const int sock, const int rx, const int tx)
{
    char msg[200];
	struct sockaddr_in srcAddr, dstAddr;
	socklen_t srcAddrLen, dstAddrLen;
	char srcClntName[INET_ADDRSTRLEN];
	char dstClntName[INET_ADDRSTRLEN];

	if (getsockname (sock, (struct sockaddr *)&srcAddr, &srcAddrLen) < 0)
		fatal ("getsockname", strerror(errno));

	if (inet_ntop( AF_INET, &(srcAddr.sin_addr.s_addr), srcClntName, sizeof(srcClntName)) == NULL)
		info ("Uname to get socket address");

	if (getpeername (sock, (struct sockaddr *) &dstAddr, &dstAddrLen) < 0)
		fatal ("getsockname", strerror(errno));

	if (inet_ntop( AF_INET, &(dstAddr.sin_addr.s_addr), dstClntName, sizeof(dstClntName)) == NULL)
		info ("Uname to get socket address");

	sprintf (msg, "%s:%d <--> %s:%d - rx:%d tx:%d", srcClntName, ntohs(srcAddr.sin_port), dstClntName, ntohs(dstAddr.sin_port), rx, tx);
	info (msg);
}

