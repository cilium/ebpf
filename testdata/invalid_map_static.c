/* This file excercises the ELF loader. It is not a valid BPF program. */

#include "common.h"

struct bpf_map_def dummy __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint64_t),
	.max_entries = 1,
	.map_flags   = 0,
};

/* The static qualifier leads to clang not emitting a symbol. */
static struct bpf_map_def hash_map __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint64_t),
	.max_entries = 1,
	.map_flags   = 0,
};

__section("xdp") int xdp_prog() {
	uint32_t key = 0;
	void *p      = map_lookup_elem(&hash_map, &key);
	return !!p;
}
