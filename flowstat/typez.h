struct packet_list_type
{
	u_int32_t len; // length of packet
	u_int32_t seq; // seq no

	struct packet_list_type *next; // pointer to next
	struct packet_list_type *prev; // pointer to prev
};

struct peer_info_node_type // sequence should be like this
{
        u_int16_t	port;
        struct in_addr  ip;
};

union peer_info_type
{
        struct peer_info_node_type info;
        u_int64_t hash;
};

struct state_bits
{
	unsigned syn:1;
	unsigned ack:1;
	unsigned rst:1;
	unsigned fin:1;
	unsigned dir:1;
	unsigned bit5:1;
	unsigned bit6:1;
	unsigned bit7:1;
};

union state_type
{
	u_int8_t value;
	struct state_bits bits;
};

struct tcp_option_type
{
	u_int8_t type;
	u_int8_t length;
};

struct session_info_type
{
        u_int32_t ack;
        u_int32_t seq;
        u_int32_t win;
	u_int16_t len;

	u_int32_t maxSeq; // maximum seq no. seen up to now
	u_int32_t lastAck; // latest ack seen in the flow
	u_int64_t expAck; // expected ack, regarding length of received packets

	u_int8_t tcp_wscaling_permitted;
	u_int8_t tcp_wscaling;

	struct packet_list_type *head; // pointer to head of list of packets
};

struct flow_type
{
        union peer_info_type           	node1;
        union peer_info_type           	node2;
        struct session_info_type        session1;
        struct session_info_type        session2;
        long int                        time_sec;
        long int                        time_usec;
        union state_type 		state;
};

struct statistic_type
{
        u_int64_t biDirFlowCounter; // bidirectional flows -
        u_int64_t uniDirFlowCounter; // bidirectional flows -
        u_int64_t staleFlowCounter; // stale flows -
        u_int64_t handshakeStaleFlowCounter; // stale flows -

        u_int64_t allPacketCounter; // all read packets -
        u_int64_t processPacketCounter;

        u_int64_t synPacketCounter; // packets with SYN flag -
        u_int64_t finPacketCounter; // packets with FIN flag -
        u_int64_t rstPacketCounter; // packets with RST flag -
        u_int64_t ackPacketCounter; // packets with ACK flag -

        u_int64_t check1ErrorCounter;
        u_int64_t winCheckErrorCounter;

	u_int64_t rawPacketErrorCounter;
};

struct process_info_type
{
        u_int8_t l2_len;

        u_int8_t processId;
        u_int8_t noOfProcess;
        pid_t pid;

        char *deviceName;
        FILE *outputFile;
        int inputPipe;
        int outputPipe;

	time_t startTime;
	time_t finTime;
};

struct flow_list_bst_type
{
        struct flow_type flow;
        struct flow_list_bst_type	*parent;
        struct flow_list_bst_type	*right;
        struct flow_list_bst_type	*left;
};

struct flow_list_bst_head_type
{
        struct flow_list_bst_type   *head; /// why pointer??????
	struct process_info_type procInfo;
	struct statistic_type procStat;
};

/*struct flow_list_type
{
        struct flow_type flow;
        struct flow_list_type *next;
        struct flow_list_type *prev;
};

struct flow_list_head_type
{
        struct flow_list_type   *head; /// why pointer??????
        struct process_info_type procInfo;
        struct statistic_type procStat;
};*/

struct packet_type
{
        union peer_info_type           	node1;
        union peer_info_type           	node2;
        struct session_info_type        info;
        long int                        time_sec;
        long int                        time_usec;
        union state_type 		state;
};

/*struct message_type
{
	struct packet_type packet;
	struct statistic_type stat;
};*/

/* Cisco HDLC frame structure
       	Address:        8 bits
       	Control:        8 bits  = 0x00
       	Protocol Code:  16 bits = 0x0800 for IP
       	Data:           ...
       	FCS:            16 bits
       	Flags:          8 bits
*/

struct chdlc_header
{
        u_int8_t  addr;
        u_int8_t  control;
        u_int16_t proto;
};

#define ETHERNET_ADDRLEN 6

struct ethernet_header
{
  u_int8_t  ether_dhost[ETHERNET_ADDRLEN];	/* destination eth addr */
  u_int8_t  ether_shost[ETHERNET_ADDRLEN];	/* source ether addr    */
  u_int16_t ether_type;                         /* packet type ID field */
};


