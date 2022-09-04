// +build ignore

#include "bpf_common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct data_t {
	__u32 fpid;
	__u32 tpid;
	__u64 pages;
	char fcomm[TASK_COMM_LEN];
	char tcomm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/oom_kill_process")
int BPF_KPROBE_oom_kill_process(struct pt_regs *ctx, struct oom_control *oc, const char *message) {
	struct data_t data;

	data.fpid  = bpf_get_current_pid_tgid() >> 32;
	data.tpid  = BPF_CORE_READ(oc, chosen, tgid);
	data.pages = BPF_CORE_READ(oc, totalpages);
	bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
	bpf_probe_read_kernel(&data.tcomm, sizeof(data.tcomm), BPF_CORE_READ(oc, chosen, comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}