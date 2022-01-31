#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "parser.h"

struct flow_tuple {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8 protocol;
};

struct bpf_map_def SEC("maps") flowtracker = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_tuple),
	.value_size = sizeof(__u64),
	.max_entries = 32,
};

SEC("prog")
int xdp_prog(struct xdp_md *ctx) {
	void *data_start = (void *)(long)ctx->data;
	void *data_end   = (void *)(long)ctx->data_end;
	struct flow_tuple flow = {};
	int ret = 0;
	__u64 new_counter = 1;
	__u64 *counter;

	struct hdr_cursor headers = {
		.start = data_start,
		.end   = data_end,
		.pos   = data_start,
	};

	ret = parse_ethernet(&headers);
	if (ret == PARSE_FAIL) {
		bpf_printk("Not enough data for ethernet header\n");
		return XDP_DROP;
	}

	if (bpf_ntohs(ret) != ETH_P_IP) {	
		bpf_printk("non-IPv4 packet\n"); // ARP.... pass it on
		return XDP_PASS;
	}

	ret = parse_ipv4(&headers);
	if (ret == PARSE_FAIL) {
		bpf_printk("Not enough data for IPv4 header\n");
		return XDP_DROP;
	}

	if (ret != IPPROTO_TCP)
		return XDP_PASS;
	
	ret = parse_tcp(&headers);
	if (ret == PARSE_FAIL) {
		bpf_printk("Could not parse TCP header\n");
		return XDP_DROP;
	}

	flow.saddr = headers.ipv4->saddr;
	flow.daddr = headers.ipv4->daddr;
	flow.sport = headers.tcp->source;
	flow.dport = headers.tcp->dest;
	flow.protocol = headers.ipv4->protocol;

	counter = bpf_map_lookup_elem(&flowtracker, &flow);
	if (counter) {
		__sync_fetch_and_add(counter, 1);
	} else {
		bpf_map_update_elem(&flowtracker, &flow, &new_counter, BPF_ANY);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
