/* This file excercises the ELF loader. It is not a valid BPF program.
 */

#include "common.h"

char __license[] __section("license") = "MIT";

struct map invalid_map __section("maps") = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = 4,
	.value_size  = 2,
	.max_entries = 1,
	.flags       = 0,
	.dummy       = 1,
};
