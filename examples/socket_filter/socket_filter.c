//go:build ignore
#include "bpf_endian.h"
#include "common.h"

#define DROP 0
#define PASS -1

#define PROTOCOL_TCP 0x6

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("socket")
int socket_fitler(struct __sk_buff *skb) {
	struct ethhdr eth;
	struct iphdr ip;
	struct tcphdr tcp;

	u32 offset = 0;

	// If bpf_skb_load_bytes() encounters an error, drop the packet directly.
	if (bpf_skb_load_bytes(skb, offset, &eth, sizeof(eth))) {
		return DROP;
	}

	if (eth.h_proto != bpf_htons(ETH_P_IP)) {
		return DROP;
	}

	offset += sizeof(eth);
	if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip))) {
		return DROP;
	}

	if (ip.protocol != PROTOCOL_TCP) {
		return DROP;
	}

	// Caculate the length of iphdr, and get the start offset of tcp layer.
	u16 ip_header_len = ip.ihl << 2;
	offset += ip_header_len;

	if (bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp))) {
		return DROP;
	}

	// Drop the packets whose src and dst ports are not '80'.
	if (tcp.source != bpf_htons(80) && tcp.dest != bpf_htons(80)) {
		return DROP;
	}

	// Pass the packets to userspace.
	return PASS;
}
