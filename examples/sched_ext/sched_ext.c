//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct sched_ext_ops {
  s32 (*init)();
  u64 flags;
  u32 timeout_ms;
  char name[128];
};

SEC(".struct_ops.link")
struct sched_ext_ops minimal_sched = {
    .name = "minimal",
    .timeout_ms = 5000,
};
