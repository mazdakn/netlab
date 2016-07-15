#ifndef __NETUTILS_H__
#define __NETUTILS_H__

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include "message.h"

void printBuffer (char *buffer, const int len);
int tuple (struct sockaddr_in *addr, const char *server, int port);
struct sockaddr_in *resolve (const char *target);
void printInfo (const int sock, const int rx, const int tx);


#endif

