#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#include <stdio.h>
#include <net/ethernet.h>

#include "ip.h"

int ethernetDecoder(const u_char *, int verbosity);
void ethernetPrinter (struct ether_header *ether_hdr);

#endif
