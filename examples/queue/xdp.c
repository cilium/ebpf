//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

/* Define packet struct data containing:
	- source IPv4 address
	- timestamp of the packet
*/
struct packet_data {
	__u32 src_ip;
	__u64 timestamp;
};

/* Define a Queue for pushing incoming IPv4 Address and timestamp for each packet */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(value, struct packet_data); // packet data struct, ip and timestamp
} queue_with_data SEC(".maps");

/*
Attempt to parse the IPv4 source address from the packet and push the address
alongside with the timestamp associated to the packet into the defined Queue.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

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

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);
	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	struct packet_data packet = {};

	if (!parse_ip_src_addr(ctx, &packet.src_ip)) {
		// Not an IPv4 packet, so skip it.
		goto done;
	}

	// IPv4 packet, compute the timestamp
	packet.timestamp = bpf_ktime_get_ns();

	// Push the structure into the Queue if there is still space,
	// otherwise just ignore it.
	bpf_map_push_elem(&queue_with_data, &packet, BPF_ANY);

done:
	return XDP_PASS;
}
