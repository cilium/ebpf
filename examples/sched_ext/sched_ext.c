//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct sched_ext_ops {
	char name[128];
};

SEC(".struct_ops.link")
struct sched_ext_ops minimal_sched = {
	.name = "minimal",
};
