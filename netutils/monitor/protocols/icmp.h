#ifndef __ICMP_H__
#define __ICMP_H__

#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

int icmpDecoder (const u_char *header, int verbosity);
void icmpPrinter (const struct icmphdr *icmp_hdr);

#endif
