#ifndef __IP_H__
#define __IP_H__

#include <stdio.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "icmp.h"
#include "tcp.h"
#include "udp.h"

int ipDecoder (const u_char *header, int verbosity);
void ipPrinter (const struct ip *ip_hdr);


#endif
