#ifndef __PACKET_H__
#define __PACKET_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint16_t checksum (uint16_t *addr, int len);
void dumpPacket(const unsigned char *, const unsigned int);
void randomPayload (uint8_t *payload, int length);



#endif
