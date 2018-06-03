/* This file excercises the ELF loader. It is not a valid BPF program.
 */

#include "common.h"

struct map hash_map __section("maps") = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = 4,
	.value_size  = 2,
	.max_entries = 1,
	.flags       = 0,
};

struct map hash_map2 __section("maps") = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = 4,
	.value_size  = 1,
	.max_entries = 2,
	.flags       = BPF_F_NO_PREALLOC,
};

struct map array_of_hash_map __section("maps") = {
	.type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.key_size = sizeof(uint32_t),
	.max_entries = 2,
	.inner_map_idx = 0, // points to "hash_map"
};

struct map hash_of_hash_map __section("maps") = {
	.type = BPF_MAP_TYPE_HASH_OF_MAPS,
	.key_size = sizeof(uint32_t),
	.max_entries = 2,
	.inner_map_idx = 1, // points to "hash_map2"
};

int __attribute__((noinline)) helper_func2(int arg) {
	return arg > 5;
}

int __attribute__((noinline)) helper_func(int arg) {
	// Enforce bpf-to-bpf call in .text section
	return helper_func2(arg);
}

__section("xdp") int xdp_prog() {
	unsigned int key = 0;
	map_lookup_elem(&hash_map, &key);
	map_lookup_elem(&hash_map2, &key);
	return helper_func(1);
}

// This function has no relocations, and is thus parsed differently.
__section("socket") int no_relocation() {
	return 0;
}
