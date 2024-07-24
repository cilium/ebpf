//go:build ignore

#include "common.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";
#define TASK_COMM_LEN 16
struct key_t {
	u32 pid;
	u8 comm[TASK_COMM_LEN];
};

struct key_t *unused __attribute__((unused));
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 10);
	__type(key, struct key_t);
	__type(value, u64);
} syscall_count_map SEC(".maps");

const volatile long target_syscall_id = -1;

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, void *regs, long syscall_id) {
	if (target_syscall_id != -1 && syscall_id != target_syscall_id) {
		return 0;
	}
	struct key_t key = {
		.pid = bpf_get_current_pid_tgid() >> 32,
	};
	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	u64 *count = bpf_map_lookup_elem(&syscall_count_map, &key);
	if (!count) {
		u64 one = 1;
		bpf_map_update_elem(&syscall_count_map, &key, &one, BPF_ANY);
	} else {
		__sync_fetch_and_add(count, 1);
	}
	return 0;
}