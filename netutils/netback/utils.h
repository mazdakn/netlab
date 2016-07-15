#ifndef __UTILS_H__
#define __UTILS_H__

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_IFACENAME 20
#define MAX_FILTERSIZE 50

#define OK 0
#define ERROR -1

struct Arguments {
        char interface[MAX_IFACENAME];
		int port;
        int verbosity;
        int dumpPkt;
};

int parseArguments(int, char**, struct Arguments*);
void help(char *);

#endif
