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

#include "message.h"


#define MAX_IFACENAME   20
#define MAX_TARGETNAME  50
#define MAX_ADDRESS     20
#define MAX_PROTOCOL    20

#define OK 0
#define ERROR -1

struct Arguments {
        char interface[MAX_IFACENAME];
        int driver;
        char target[MAX_TARGETNAME];
        char source[MAX_ADDRESS];
        int length;                     //payload length
        char generator[MAX_PROTOCOL];
        int frequency;
        int verbosity;
        int dumpPkt;
	int port;
};

int parseArguments(int argc, char *argv[], struct Arguments* args);
void help (char *name);

#endif
