/* This file excercises the ELF loader.
 */

#include "common.h"

char __license[] __section("license") = "MIT";

struct bpf_map_def hash_map __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint64_t),
	.max_entries = 1,
};

static int sub_prog() {
	uint32_t key = 0;
	uint64_t val = 42;

	map_update_elem(&hash_map, &key, &val, /* BPF_ANY */ 0);

	return 0;
}

__section("xdp") int fp_relocation() {
	uint32_t key = 0;
	uint64_t val = 1;

	map_update_elem(&hash_map, &key, &val, /* BPF_ANY */ 0);

	for_each_map_elem(&hash_map, sub_prog, (void *)0, 0);

	uint64_t *new_val = map_lookup_elem(&hash_map, &key);
	if (!new_val) {
		return -1;
	}

	return *new_val;
}
