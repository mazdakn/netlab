#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "general.h"

#define MAX_IFACENAME   20
#define MAX_SERVER      20


struct Arguments {
    char interface[MAX_IFACENAME];
	int listen;
	char server[MAX_SERVER]; //fix it
	int port;
	int verbosity;
	int dumpPkt;
};

int parseArguments(int argc, char *argv[], struct Arguments* args);
void help (char *name);


#endif
