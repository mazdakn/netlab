#ifndef __TCPSOCKET_H__
#define __TCPSOCKET_H__

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include "message.h"
#include "signalhandler.h"
#include "netutils.h"

int serverSocket (const int port);
int clientSocket (struct sockaddr_in *srvAddr);
int connectSocket(const int srvSock);
int readSock (const int sock, char *data, const int len);
int sendSock (const int sock, char  *data, const int len);
int forwardToSocket (const int srcSock, const int dstSock);
int forwardToSocketLoop (const int srcSock, const int dstSock);
int nonBlockingSocket (const int sock);

#endif
