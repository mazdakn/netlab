#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <time.h>
#include <sys/wait.h>

#include "typez.h"

#define MAX_NO_PROCCESS 50 //maximum no. of processes

// parser.c
extern void PacketParser(u_char *user, const struct pcap_pkthdr *header,const u_char *payload);

//output-bst.c
extern void showResultBST(struct flow_list_bst_head_type *flowList);
extern void showFinalResultBST(struct flow_list_bst_head_type *flowList);

