#include "tcpproxy.h"
	
int tcpproxy(const struct Arguments *args)
{ 
	fd_set rfds;
	int ret;
	struct sockaddr_in rmtAddr;
	int max_sock;
	int sSock = 0, cSock = 0, rSock = 0;
	struct timeval tv;

	sSock = serverSocket (args->listen);
	max_sock = sSock;

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	while (checkSignal()) {
	
		if (!rSock) {
			tuple (&rmtAddr, args->server, args->port);
			rSock = clientSocket (&rmtAddr);
			if (rSock > max_sock) max_sock = rSock;
		}
	
		FD_ZERO (&rfds);
		FD_SET (sSock, &rfds);
		
		if (cSock) FD_SET (cSock, &rfds);
		if (rSock) FD_SET (rSock, &rfds);

		ret = select (max_sock + 1, &rfds, NULL, NULL, &tv);

		if ((ret < 0 ) && (errno != EINTR))
			fatal ("select", strerror (errno));
	
		if ((FD_ISSET (sSock, &rfds)) && (!cSock)) {
			cSock = connectSocket (sSock);
			if (cSock > max_sock) max_sock = cSock;
		}

		if ((FD_ISSET (cSock, &rfds)) && (!cSock))
			if (forwardToSocket (cSock, rSock) <= 0) {
				printf ("closing socket\n"); // make it a funcion
				close (cSock);
				cSock = 0;
			}
		
		if (FD_ISSET (rSock, &rfds))
		{
			if (forwardToSocket (rSock, cSock) <= 0) {
				printf ("error connection to remote\n");
				close (rSock);
				rSock = 0;
			}
		}
	}

	return 0;
}

