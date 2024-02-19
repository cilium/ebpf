//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Session identifier
struct session_key {
	__u32 saddr; // IP source address
	__u32 daddr; // IP dest address
	__u16 sport; // Source port (if ICMP then 0)
	__u16 dport; // Dest port (if ICMP then 0)
	__u8 proto; // Protocol ID
};

// Session value
struct session_value {
	__u32 in_count;
	__u32 eg_count;
};

#define MAX_MAP_ENTRIES 16

/*
Define an Hash map for storing packet Ingress and Egress count by 5-tuple session identifier
User-space logic is responsible for cleaning the map, if potentially new entries needs to be monitored.
*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, struct session_key);
	__type(value, struct session_value);
} stats_map SEC(".maps");

/*
Attempt to parse the 5-tuple session identifierfrom the packet.
Returns 0 if there is no IPv4 header field or if L4 is not a UDP, TCP or ICMP packet; otherwise returns non-zero.
*/
static __always_inline int parse_session_identifier(void *data, void *data_end, struct session_key *key, __u8 is_ingress) {
	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	// Then parse the L4 header.
	switch (ip->protocol) {
	case IPPROTO_TCP: {
		// TCP protocol carried, parse TCP header.
		struct tcphdr *tcp = (void *)(ip + 1);
		if ((void *)(tcp + 1) > data_end)
			return 0;
		key->sport = (__u16)(tcp->source);
		key->dport = (__u16)(tcp->dest);
		break;
	}
	case IPPROTO_UDP: {
		// UDP protocol carried, parse TCP header.
		struct udphdr *udp = (void *)(ip + 1);
		if ((void *)(udp + 1) > data_end)
			return 0;
		key->sport = (__u16)(udp->source);
		key->dport = (__u16)(udp->dest);
		break;
	}
	case IPPROTO_ICMP: {
		// ICMP protocol carried, no source/dest port.
		break;
	}
	// Unchecked protocols, ignore them
	default: {
		return 0;
	}
	}

	// Fill session key with IP header data
	key->proto = (__u8)(ip->protocol);
	key->saddr = (__u32)(ip->saddr);
	key->daddr = (__u32)(ip->daddr);

	// In case the function is called from Egress hook, swap IP addresses and L4 ports before
	// doing the map lookup
	if (!is_ingress) {
		__u32 tmp  = key->saddr;
		key->saddr = key->daddr;
		key->daddr = tmp;
		__u16 tmp2 = key->sport;
		key->sport = key->dport;
		key->dport = tmp2;
	}
	return 1;
}

/*
Main program logic shared by either XDP and TC hook. The function attempts to update the entry
in the LRU map corresponding to the 5-tuple identifier; it increases either the ingress or egress
packet counter value. In case of a non IP, TCP, UDP, ICMP packet, the program ignores the packet.
*/
static __always_inline int prog_logic(void *data, void *data_end, __u8 is_ingress, int ret_code) {
	struct session_key key = {};
	if (!parse_session_identifier(data, data_end, &key, is_ingress)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}

	struct session_value *val = bpf_map_lookup_elem(&stats_map, &key);
	if (!val) {
		// No entry in the map for this 5-tuple identifier yet, so set the initial value to 1.
		struct session_value new_val = {};
		if (is_ingress)
			new_val.in_count = 1;
		else
			new_val.eg_count = 1;
		bpf_map_update_elem(&stats_map, &key, &new_val, BPF_ANY);
	} else {
		// Entry already exists for this 5-tuple identifier, so increment it atomically using an LLVM built-in.
		if (is_ingress)
			__sync_fetch_and_add(&val->in_count, 1);
		else
			__sync_fetch_and_add(&val->eg_count, 1);
	}

done:
	// Return code corresponds to the OK action within either XDP or TC
	return ret_code;
}

// XDP Ingress hook
SEC("xdp")
int ingress_prog_func(struct xdp_md *ctx) {
	return prog_logic((void *)(long)ctx->data, (void *)(long)ctx->data_end, 0, XDP_PASS);
}

// TC Egress hook
SEC("tc")
int egress_prog_func(struct __sk_buff *ctx) {
	return prog_logic((void *)(long)ctx->data, (void *)(long)ctx->data_end, 1, TC_ACT_OK);
}
