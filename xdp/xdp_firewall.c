#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "parser.h"

SEC("xdp_firewall")
int packet_drop(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data 	   = (void *)(long)ctx->data;
	int next_header;
	
	struct ethhdr *ethernet = NULL;
	next_header = parse_ethernet(data, data_end, ethernet);
	
	if (next_header < 0) {
		bpf_printk("xdpfw: unknown packet\n");
		return XDP_DROP; // should have enough bytes for ethernet header
	}

	if (next_header != ETH_P_IP) {
		bpf_printk("xdpfw: unknown next header %d \n", next_header);
		return XDP_PASS; // pass anything beside IPv4
	}

	/* used a switch to check different protocols?
	switch (next_header) {
	case ETH_P_IP:

	case default:
		bpf_printk("ethernet parser: next protocol %d\n", next_header);
		return XDP_DROP;
	} */

	struct iphdr *ip = NULL;
	next_header = parse_ipv4(data, data_end, ip);
	if (next_header < 0) {
		//bpf_trace_printk("xdpfw: unknown L3 packet");
		return XDP_DROP;
	}

	if (next_header == IPPROTO_UDP) {
		return XDP_DROP;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
