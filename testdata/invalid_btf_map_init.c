/* This file excercises the ELF loader. It is not a valid BPF program. */

#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint64_t);
	__uint(max_entries, 1);
} hash_map __section(".maps") = {
	/* This forces a non-zero byte into the .maps section. */
	.key = (void *)1,
};
