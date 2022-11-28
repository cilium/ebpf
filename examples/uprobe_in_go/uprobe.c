// +build ignore

#include "common.h"

#define MAX_ARG_LEN 100

char __license[] SEC("license") = "Dual MIT/GPL";

#define SARG(ctx, n, v) bpf_probe_read(&(v), sizeof((v)), (void *)(PT_REGS_SP(ctx)) + 8 * (n + 1))

struct event {
	u64 pid_tgid;

	u8 arg0[MAX_ARG_LEN];
	u8 arg0_length;
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("uprobe/main_print")
int uprobe__main_print(struct pt_regs *ctx) {
	u64 arg0_addr = 0;
	u64 arg0_len  = 0;

	struct event event = {};
	event.pid_tgid     = bpf_get_current_pid_tgid();

	SARG(ctx, 0, arg0_addr);
	SARG(ctx, 1, arg0_len);
	bpf_probe_read(&event.arg0, sizeof(event.arg0), (const void *)(arg0_addr));
	event.arg0_length = arg0_len;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}
