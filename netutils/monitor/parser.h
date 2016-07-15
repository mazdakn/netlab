#ifndef __PARSER_H__
#define __PARSER_H__

#include <string.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


#include <pcap/pcap.h>

#include "utils.h"
#include "protocols/ethernet.h"
#include "signalhandler.h"
#include "packet.h"

void pktParser(u_char *, const struct pcap_pkthdr *, const u_char *);

#endif
