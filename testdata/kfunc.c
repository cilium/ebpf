#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

// CO-RE type compat checking doesn't allow matches between forward declarations
// and structs so we can't use forward declarations. Empty structs work just fine.
struct __sk_buff {};
struct nf_conn {};
struct bpf_sock_tuple {};
struct bpf_ct_opts {};
struct bpf_cpumask {};

extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *, struct bpf_sock_tuple *, uint32_t, struct bpf_ct_opts *, uint32_t) __ksym;
extern void bpf_ct_release(struct nf_conn *) __ksym;

__section("tc") int call_kfunc(void *ctx) {
	char buf[1];
	struct nf_conn *conn = bpf_skb_ct_lookup(ctx, (void *)buf, 0, (void *)buf, 0);
	if (conn) {
		bpf_ct_release(conn);
	}
	return 1;
}

extern int bpf_fentry_test1(int) __ksym;

__section("fentry/bpf_fentry_test2") int benchmark() {
	// bpf_fentry_test1 is a valid kfunc but not allowed to be called from
	// TC context. We use this to avoid loading a gajillion programs into
	// the kernel when benchmarking the loader.
	return bpf_fentry_test1(0);
}

extern void invalid_kfunc(void) __ksym __weak;

extern struct bpf_cpumask *bpf_cpumask_create(void) __ksym __weak;
extern void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym __weak;

__section("tp_btf/task_newtask") int weak_kfunc_missing(void *ctx) {
	if (bpf_ksym_exists(invalid_kfunc)) {
		invalid_kfunc();
		return 0;
	}

	return 1;
}

__section("tp_btf/task_newtask") int call_weak_kfunc(void *ctx) {
	if (bpf_ksym_exists(bpf_cpumask_create)) {
		struct bpf_cpumask *mask = bpf_cpumask_create();
		if (mask)
			bpf_cpumask_release(mask);

		return 1;
	}

	return 0;
}
