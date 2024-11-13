//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

__u64 ingress_pkt_count = 0;
__u64 egress_pkt_count  = 0;

SEC("tc")
int ingress_prog_func(struct __sk_buff *skb) {
	__sync_fetch_and_add(&ingress_pkt_count, 1);
	return TC_ACT_OK;
}

SEC("tc")
int egress_prog_func(struct __sk_buff *skb) {
	__sync_fetch_and_add(&egress_pkt_count, 1);
	return TC_ACT_OK;
}
