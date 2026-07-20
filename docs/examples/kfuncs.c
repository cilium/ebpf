//go:build ignore

// kfuncs_required {
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *skb_ctx, struct bpf_sock_tuple *bpf_tuple, __u32 tuple__sz, struct bpf_ct_opts *opts, __u32 opts__sz) __ksym;
extern void bpf_ct_release(struct nf_conn *ct) __ksym;

SEC("tc")
int lookup_conntrack(struct __sk_buff *skb) {
	struct bpf_sock_tuple tuple = {};
	struct bpf_ct_opts opts     = {};
	struct nf_conn *ct;

	ct = bpf_skb_ct_lookup(skb, &tuple, sizeof(tuple.ipv4), &opts, sizeof(opts));
	if (!ct)
		return 0;

	bpf_ct_release(ct);
	return 0;
}
// }

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
