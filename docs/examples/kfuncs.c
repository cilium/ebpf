//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// kfuncs_optional {
struct bpf_cpumask;

extern struct bpf_cpumask *bpf_cpumask_create(void) __ksym __weak;
extern void bpf_cpumask_release(struct bpf_cpumask *mask) __ksym __weak;

SEC("tp_btf/task_newtask")
int maybe_use_cpumask(void *ctx) {
	struct bpf_cpumask *mask;

	if (!bpf_ksym_exists(bpf_cpumask_create) || !bpf_ksym_exists(bpf_cpumask_release))
		return 0;

	mask = bpf_cpumask_create();
	if (mask)
		bpf_cpumask_release(mask);

	return 0;
}
// }
