// getting_started_counter {
// (1)!
//go:build ignore

#include <linux/bpf.h> // (2)!
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); // (3)!
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} pkt_count SEC(".maps"); // (4)!

// count_packets atomically increases a packet counter on every invocation.
SEC("xdp") // (5)!
int count_packets() {
	__u32 key    = 0; // (6)!
	__u64 *count = bpf_map_lookup_elem(&pkt_count, &key); // (7)!
	if (count) { // (8)!
		__sync_fetch_and_add(count, 1); // (9)!
	}

	return XDP_PASS; // (10)!
}

char __license[] SEC("license") = "Dual MIT/GPL"; // (11)!

// }
