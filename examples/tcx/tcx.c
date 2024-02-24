//go:build ignore

#include "common.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Session identifier
struct session_key {
	__u32 saddr; // IP source address
	__u32 daddr; // IP dest address
	__u16 sport; // Source port (set to 0 if ICMP)
	__u16 dport; // Dest port (set to 0 if ICMP)
	__u8 proto; // Protocol ID
};

// Session value
struct session_value {
	__u32 in_count; // Ingress packet count
	__u32 eg_count; // Egress packet count
};

#define MAX_MAP_ENTRIES 16

// Define an Hash map for storing packet Ingress and Egress count by 5-tuple session identifier
// User-space logic is responsible for cleaning the map, if potentially new entries needs to be monitored.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, struct session_key);
	__type(value, struct session_value);
} stats_map SEC(".maps");

// Attempt to parse the 5-tuple session identifier from the packet.
// Returns 0 if the operation failed, i.e. not IPv4 packet or not UDP, TCP or ICMP.
static __always_inline int parse_session_identifier(void *data, void *data_end, struct session_key *key) {
	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	// Check for IPv4 packet.
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
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
		// UDP protocol carried, parse UDP header.
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
	// Unchecked protocols, ignore packet and return.
	default: {
		return 0;
	}
	}

	// Fill session key with IP header data
	key->proto = (__u8)(ip->protocol);
	key->saddr = (__u32)(ip->saddr);
	key->daddr = (__u32)(ip->daddr);

	return 1;
}

// TC Ingress hook, to monitoring TCP/UDP/ICMP network connections and count packets.
SEC("tc")
int ingress_prog_func(struct __sk_buff *skb) {
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct session_key key = {};
	if (!parse_session_identifier(data, data_end, &key)) {
		goto ingress_done;
	}

	struct session_value *val = bpf_map_lookup_elem(&stats_map, &key);
	if (!val) {
		// No entry in the map for this 5-tuple identifier yet, so set the initial value to 1.
		struct session_value new_val = {.in_count = 1};
		bpf_map_update_elem(&stats_map, &key, &new_val, BPF_ANY);
		goto ingress_done;
	}

	// Entry already exists for this 5-tuple identifier, so increment it atomically using an LLVM built-in.
	__sync_fetch_and_add(&val->in_count, 1);

ingress_done:

	// Return code corresponds to the PASS action in TC
	return TC_ACT_OK;
}

// TC Egress hook, same as Ingress but with IPs and Ports inverted in the key.
// This way, the connections match the same entry for the Ingress in the bpf map.
SEC("tc")
int egress_prog_func(struct __sk_buff *skb) {
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct session_key key = {};
	if (!parse_session_identifier(data, data_end, &key)) {
		goto egress_done;
	}

	// Swap addresses and L4 port before doing the map lookup.
	__u32 tmp  = key.saddr;
	__u16 tmp2 = key.sport;
	key.saddr  = key.daddr;
	key.sport  = key.dport;
	key.daddr  = tmp;
	key.dport  = tmp2;

	struct session_value *val = bpf_map_lookup_elem(&stats_map, &key);
	if (!val) {
		// No entry in the map for this 5-tuple identifier yet, so set the initial value to 1.
		struct session_value new_val = {.eg_count = 1};
		bpf_map_update_elem(&stats_map, &key, &new_val, BPF_ANY);
		goto egress_done;
	}

	// Entry already exists for this 5-tuple identifier, so increment it atomically using an LLVM built-in.
	__sync_fetch_and_add(&val->eg_count, 1);

egress_done:

	// Return code corresponds to the PASS action in TC
	return TC_ACT_OK;
}
