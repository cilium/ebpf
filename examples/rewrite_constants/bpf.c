//go:build ignore

#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} syscall_count_map SEC(".maps");

const volatile long target_syscall_id = -1;

const u32 key = 0;

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, void *regs, long syscall_id) {
	if (target_syscall_id != -1 && syscall_id != target_syscall_id) {
		return 0;
	}

	u64 *count = bpf_map_lookup_elem(&syscall_count_map, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
	}
	return 0;
}