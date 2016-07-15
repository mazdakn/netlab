#include "tcploop.h"
	
int tcploop(const int port)
{
	int cSock = 0;
	int sSock = serverSocket (port);
	fd_set rfds;
	int max_sock, ret;
	struct timeval tv;

	max_sock = sSock;

	while (checkSignal()) {

		FD_ZERO (&rfds);
		FD_SET (sSock, &rfds);

		if (cSock) FD_SET (cSock, &rfds);

		tv.tv_sec = 1; // a parameter
		tv.tv_usec = 0;

        ret = select (max_sock + 1, &rfds, NULL, NULL, &tv);

		if (errno == EINTR) continue;

		if ((ret < 0))
			fatal ("select", strerror (errno));

		if ((!cSock) && (FD_ISSET (sSock, &rfds))) {
			cSock = connectSocket (sSock);
			if (cSock > max_sock) max_sock = cSock;
		}

		if ((cSock) && (FD_ISSET (cSock, &rfds))) {
				if (forwardToSocket (cSock, cSock) <= 0) {
					info ("closing socket"); // make it a funcion
					close (cSock);
					cSock = 0;
				}
		}
	}

	return 0;

}
