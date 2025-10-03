//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct sched_ext_ops {
	__s32 (*init)(void);
	void (*runnable)(void *, __u64);
	void (*running)(void *);
	void (*stopping)(void *, __u8);
	void (*quiescent)(void *, __u64);
	__u8 (*yield)(void *, void *);
	__u32 timeout_ms;
	char name[128];
};

SEC("struct_ops/scx_runnable")
int scx_runnable(void *p, __u64 enq_flags) {
	bpf_printk("scheduler runnable\n");
	return 0;
};

SEC("struct_ops/scx_running")
int scx_running(void *p) {
	bpf_printk("scheduler running\n");
	return 0;
};

SEC("struct_ops/scx_stopping")
int scx_stopping(void *p, __u8 runnable) {
	bpf_printk("scheduler stopping\n");
	return 0;
};

SEC("struct_ops/scx_quiescent")
int scx_quiescent(void *p, __u64 deq_flags) {
	bpf_printk("scheduler quiescent\n");
	return 0;
};

SEC("struct_ops/scx_yield")
int scx_yield(void *from, void *to) {
	bpf_printk("scheduler yield\n");
	return 0;
};

SEC("struct_ops.s/scx_init")
int scx_init(void) {
	bpf_printk("scheduler init\n");
	return 0;
};

SEC(".struct_ops.link")
struct sched_ext_ops scx = {
	.init       = (void *)scx_init,
	.running    = (void *)scx_running,
	.runnable   = (void *)scx_runnable,
	.stopping   = (void *)scx_stopping,
	.quiescent  = (void *)scx_quiescent,
	.yield      = (void *)scx_yield,
	.timeout_ms = 10000U,
	.name       = "scx",
};
