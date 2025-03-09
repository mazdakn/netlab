#ifndef __UDPSOCKET_H__
#define __UDPSOCKET_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h> 

#include "utils.h"

#define PACKET_SIZE 1316	// packet size
#define HEADER_SIZE sizeof(struct Header) // header size
#define PACKET_TOKEN 0x2309 // packet token

#define DEFAULT_IDEALTIME 10 // 10msec time slots
#define MSEC_FACTOR 1000 // factor to change from usec to msec

// packet header structure
struct Header {
    uint32_t pkt_cnt;	// counter
    uint16_t pkt_token;	// 0x2309
    uint8_t  pkt_flag1; // flag1 
    uint8_t  pkt_flag2; // flag2 = ~flag1
};

// function declration
int createUDPSocket (struct Arguments *);
void closeUDPSocket (int);
char *createPacket (uint32_t);
void transmit (int , struct Arguments *);

#endif
