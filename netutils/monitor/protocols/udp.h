#ifndef __UDP_H__
#define __UDP_H__

#include <stdio.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

int udpDecoder (const u_char *header, int verbosity);
void udpPrinter (const struct udphdr *udp_hdr);

#endif
