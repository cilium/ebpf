/* This file is used for benchmarking NewCollection().
 */

#include "../btf/testdata/bpf_core_read.h"
#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

struct bpf_map_def __section("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint64_t),
	.max_entries = 128,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key)                                   = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, uint64_t flags) = (void *)2;
static void *(*bpf_get_current_task)()                                                            = (void *)35;
static long (*bpf_probe_read_kernel)(void *dst, uint32_t size, const void *unsafe_ptr)            = (void *)113;

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
struct ns_common {
	unsigned int inum;
};
struct mnt_namespace {
	struct ns_common ns;
};
struct nsproxy {
	struct mnt_namespace *mnt_ns;
};
struct task_struct {
	struct nsproxy *nsproxy;
};
#pragma clang attribute pop

static inline int impl() {
	uint64_t initval = 1, *valp;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	uint32_t mntns           = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	valp = bpf_map_lookup_elem(&kprobe_map, &mntns);
	if (!valp) {
		bpf_map_update_elem(&kprobe_map, &mntns, &initval, 0);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);

	return 0;
}

#define DEFINE_PROBE(i) \
	__section("kprobe/sys_execvea" #i) int kprobe_execve##i() { \
		return impl(); \
	}

DEFINE_PROBE(0);
DEFINE_PROBE(1);
DEFINE_PROBE(2);
DEFINE_PROBE(3);
DEFINE_PROBE(4);
DEFINE_PROBE(5);
DEFINE_PROBE(6);
DEFINE_PROBE(7);
DEFINE_PROBE(8);
DEFINE_PROBE(9);

DEFINE_PROBE(10);
DEFINE_PROBE(11);
DEFINE_PROBE(12);
DEFINE_PROBE(13);
DEFINE_PROBE(14);
DEFINE_PROBE(15);
DEFINE_PROBE(16);
DEFINE_PROBE(17);
DEFINE_PROBE(18);
DEFINE_PROBE(19);

DEFINE_PROBE(20);
DEFINE_PROBE(21);
DEFINE_PROBE(22);
DEFINE_PROBE(23);
DEFINE_PROBE(24);
DEFINE_PROBE(25);
DEFINE_PROBE(26);
DEFINE_PROBE(27);
DEFINE_PROBE(28);
DEFINE_PROBE(29);
