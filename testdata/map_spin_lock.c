/* This file excercises bpf_spin_lock. */

#include "common.h"

struct bpf_spin_lock {
	uint32_t val;
};

struct hash_elem {
	int cnt;
	struct bpf_spin_lock lock;
};

#if __clang_major__ >= 9
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, struct hash_elem);
	__uint(max_entries, 2);
} spin_lock_map __section(".maps");
#else
#error This file required clang >= 9
#endif
