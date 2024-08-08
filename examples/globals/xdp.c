//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

// Initialized to zero 	-> .bss
__u64 pkt_count = 0;

// Initialized to != 0 	-> .data
__u32 random   = 1;
char var_msg[] = "I can change :)";

// Constant variable 	-> .rodata
const char const_msg[] = "I'm constant :)";

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	pkt_count++;

	bpf_printk("pkt_count=%20llu, random=%10u, const_msg=%s, var_msg=%s", pkt_count, random, const_msg, var_msg);

	return XDP_PASS;
}
