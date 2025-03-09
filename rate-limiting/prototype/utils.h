#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>

#define OK 0
#define ERROR -1

#define DEFAULT_PORT 4000 // default port number
#define DEFAULT_PACKETS 60000 // default number of packets to send
#define DEFAULT_SPEED 5000 // default transmission rate

struct Arguments {
    char address[INET_ADDRSTRLEN];
    uint16_t port;
	uint32_t packets;
	uint16_t speed;
};

// functions declaration
int parseArguments(int , char **, struct Arguments* );
void help (const char *);
int checkNumber (const char *);
void fatal (const char *);
void error (const char *);
void info (const char *);

#endif
