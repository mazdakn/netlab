#ifndef __TCP_H__
#define __TCP_H__

#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

int tcpDecoder (const u_char *header, int verbosity);
void tcpPrinter (const struct tcphdr *tcp_hdr);

#endif
