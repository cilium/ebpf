/* This file excercises the ELF loader. It is not a valid BPF program. */

#include "common.h"

#if __clang_major__ >= 9
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint64_t);
	__uint(max_entries, 1);
} hash_map __section(".maps") = {
	/* This forces a non-zero byte into the .maps section. */
	.key = (void *)1,
};
#else
#error This file has to be compiled with clang >= 9
#endif
