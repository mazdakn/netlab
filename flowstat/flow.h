#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <pcap/pcap.h>

#include "typez.h"

#define SET 1	//check if a bit is set
#define UNSET 0 // to check bits

// flow states
#define NIL 0   // no flow and for other variable initialization
#define OPEN 192 // flow state, when SYN/ACK is received
#define CLOSE1 64 // flow state, when FIN received in one direction
#define CLOSE2 128 //flow state, when FIN is received in another direction
#define CLOSE 64 // to check if flow is closed in both direction

#define STALE_PERIOD 120 //flow inactivity period
#define BIDIRECTIONAL_FLOW_PERIOD 30 //time for decision that flow is bi directional

#define SYN 1 // SYN flag
#define ACK 2 // ACk flag
#define RST 4 // RST flag
#define FIN 8 // FIN flag
#define REV 16 // packet direction

#define SEQ_LIMIT 0xffffffff //4294967295 // for TCP seq wrap arounding
#define SEQ_MOD 0x100000000 //4294967296 // same as above

#define TCP_NORMAL_HEADER_LEN 20 //normal header length of TCP

// output-bst.c
void showPacketBST(struct flow_list_bst_head_type *flowList, struct packet_type *ptr);
void showFlowBST(struct flow_list_bst_head_type *flowList, struct flow_list_bst_type *ptr);
void showResultBST(struct flow_list_bst_head_type *flowList);
void showFinalResultBST(struct flow_list_bst_head_type *flowList);

//parser.c
void PacketParser(u_char *user, const struct pcap_pkthdr *header,const u_char *payload);

//flow-bst.c
struct flow_list_bst_type *searchFlowBST(struct flow_list_bst_head_type *flowList, struct packet_type *packet);
struct flow_list_bst_type *insertFlowBST(struct flow_list_bst_head_type *flowList,struct packet_type *packet);
void deleteFlowBST(struct flow_list_bst_type *flow);

//packet.c
struct packet_list_type *insertPacket(struct packet_list_type *head, u_int32_t packetSeq, u_int32_t packetLen);
void deletePacket (struct packet_list_type *packet);
void deleteAllPackets (struct packet_list_type *head);
struct packet_list_type *searchPacket(struct packet_list_type *head, u_int32_t packetSeq);




