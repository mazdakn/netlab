#ifndef __XDP_H__
#define __XDP_H__

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define ETH_SIZE  (sizeof(struct ethhdr))
#define IP_SIZE   (sizeof(struct iphdr))
#define ICMP_SIZE (sizeof(struct icmphdr))
#define UDP_SIZE  (sizeof(struct udphdr))
#define TCP_SIZE  (sizeof(struct tcphdr))

#define PARSE_OK 	0
#define PARSE_FAIL -1

struct hdr_cursor {
	void *start;
	void *end;
	void *pos;
	struct ethhdr *eth;
	struct iphdr  *ipv4;
	struct icmphdr   *icmp;
	struct tcphdr *tcp;
	struct udphdr *udp;
};

static __always_inline void print_cursor(struct hdr_cursor *headers) {
	bpf_printk("start: %lu end: %lu pos: %lu \n", headers->start, headers->end,
												headers->pos);
}

// TODO: Fix the return values
static __always_inline int validate_ptrs(struct hdr_cursor *headers, int size) {
	if (headers->pos + size > headers->end) {
		bpf_printk("not enough data-> start: %lu end: %lu size: %d\n", headers->start, 
																headers->end, size);
		return PARSE_FAIL;
	}

	return PARSE_OK;
}

static __always_inline int parse_ethernet(struct hdr_cursor *headers) {
	if (validate_ptrs(headers, ETH_SIZE))
		return PARSE_FAIL;

	headers->eth = headers->pos;
	headers->pos += ETH_SIZE;
	return headers->eth->h_proto;
}

static __always_inline int parse_ipv4(struct hdr_cursor *headers) {
	if (validate_ptrs(headers, IP_SIZE))
    	return PARSE_FAIL;

	headers->ipv4 = headers->pos;
	headers->pos += IP_SIZE;
	return headers->ipv4->protocol;
}

static __always_inline int parse_icmp(struct hdr_cursor *headers) {
	if (validate_ptrs(headers, ICMP_SIZE))
    	return PARSE_FAIL;

	headers->icmp = headers->pos;
	headers->pos += ICMP_SIZE;
	return headers->icmp->type;
}

static __always_inline int parse_tcp(struct hdr_cursor *headers) {
	if (validate_ptrs(headers, TCP_SIZE))
    	return PARSE_FAIL;

	headers->tcp = headers->pos;
	headers->pos += TCP_SIZE;
	return PARSE_OK;
}

static __always_inline int parse_udp(struct hdr_cursor *headers) {
	if (validate_ptrs(headers, UDP_SIZE))
    	return  PARSE_FAIL;

	headers->udp = headers->pos;
	headers->pos += UDP_SIZE;
	return PARSE_OK;
}

#endif
