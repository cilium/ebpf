/* This file tests rewriting constants from C compiled code.
 */

#include "common.h"

char __license[] __section("license") = "MIT";

struct map map_val __section("maps") = {
	.type        = 1,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 1,
};

const unsigned int constant;
#define VALUE_OF(x) ((typeof(x))(&x))

__section("xdp") int rewrite() {
	unsigned long acc = 0;
	acc |= VALUE_OF(constant);
	return acc;
}

__section("xdp/map") int rewrite_map() {
	unsigned int key = 0;
	unsigned int *value = map_lookup_elem(&map_val, &key);
	if (!value) {
		return 0;
	}
	return *value;
}
