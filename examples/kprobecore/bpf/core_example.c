#include "vmlinux.h"

#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

SEC("license") char _license[] = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} pipe SEC(".maps");

const __be16 ETH_P_IP   = 0x0800;
const __be16 ETH_P_IPV6 = 0x86DD;

struct event_t {
	struct in6_addr src_addr, dest_addr;
	uint8_t state;
};

SEC("kprobe/__neigh_event_send")
int BPF_KPROBE(kprobe____neigh_event_send, struct neighbour *neigh, struct sk_buff *skb) {
	// The BPF_CORE_READ macro is a useful macro that abstracts away the
	// complexity of accessing kernel struct fields in a relocatable way.
	//
	// In this case, we're dereferencing and reading the protocol field
	// from the skb. Equivalent to skb->protocol.
	__be16 proto = bpf_ntohs(BPF_CORE_READ(skb, protocol));

	// Skip all non-IP packets.
	if (proto != ETH_P_IP && proto != ETH_P_IPV6) {
		return 0;
	}

	// Get the head pointer from the skb, which should point to the
	// start of packet headers. We later use this to access an offset
	// into the headers.
	u8 *head = (u8 *)(long)BPF_CORE_READ(skb, head);

	// The skb contains a field which tells us the offset of the network
	// header, in our case this is either an IP or IPv6 header.
	// We can add this to head and know exactly where in kernel memory
	// we should start reading.
	u16 nh_offset = BPF_CORE_READ(skb, network_header);

	struct event_t event = {0};
	event.state          = BPF_CORE_READ(neigh, nud_state);

	switch (proto) {
	case ETH_P_IP: {
		// We create an instance of the IP header on the BPF stack.
		struct iphdr ip;

		// bpf_core_read should be used in the same way we would typically
		// use bpf_probe_read_kernel, as it's the same thing underneath!
		// The name is annoying, since the only difference with the other
		// macro is upper/lower case. But they operate very differently. In
		// this case we use this to read arbitrary amounts of kernel memory,
		// and copy it onto the BPF stack. Here we tell it to read the
		// length of an IP header in bytes from the determined offset from
		// the head pointer, and to dump it onto the stack. Retuns 0 on
		// success.s
		if (bpf_core_read(&ip, sizeof(struct iphdr), head + nh_offset) != 0) {
			return 0;
		};

		// We'll use v4 mapped v6 addresses.
		event.src_addr.in6_u.u6_addr16[5]  = 0xffff;
		event.dest_addr.in6_u.u6_addr16[5] = 0xffff;

		event.src_addr.in6_u.u6_addr32[3]  = ip.saddr;
		event.dest_addr.in6_u.u6_addr32[3] = ip.daddr;
		break;
	}
	case ETH_P_IPV6: {
		// Pretty much the same as above.
		struct ipv6hdr ip6;
		if (bpf_core_read(&ip6, sizeof(struct ipv6hdr), head + nh_offset) != 0) {
			return 0;
		};

		event.src_addr  = ip6.saddr;
		event.dest_addr = ip6.daddr;
		break;
	}
	}

	bpf_perf_event_output(ctx, &pipe, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}
