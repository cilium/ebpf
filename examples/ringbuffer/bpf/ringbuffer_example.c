#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
	u32 pid;
	char comm[80];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event_t *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
	if (!task_info) {
		return 0;
	}

	task_info->pid = tgid;
	bpf_get_current_comm(&task_info->comm, 80);

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}
