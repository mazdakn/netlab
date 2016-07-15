#ifndef __TCP_H__
#define __TCP_H__

#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)


#include "utils.h"
#include "packet.h"
#include "signalhandler.h"
#include "memory.h"

int initTCP(struct Arguments *args);
int loopTCP(struct Arguments *args, const int sock);


#endif
