//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/* Define an ARRAY map for storing ingress packet count */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} ingress_pkt_count SEC(".maps");

/* Define an ARRAY map for storing egress packet count */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} egress_pkt_count SEC(".maps");

/*
Upon arrival of each network packet, retrieve and increment
the packet count from the provided map.
Returns TC_ACT_OK, allowing the packet to proceed.
*/
static __always_inline int update_map_pkt_count(void *map) {
	__u32 key    = 0;
	__u64 *count = bpf_map_lookup_elem(map, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
	}

	return TC_ACT_OK;
}

SEC("tc")
int ingress_prog_func(struct __sk_buff *skb) {
	return update_map_pkt_count(&ingress_pkt_count);
}

SEC("tc")
int egress_prog_func(struct __sk_buff *skb) {
	return update_map_pkt_count(&egress_pkt_count);
}
