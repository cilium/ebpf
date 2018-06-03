/* This file tests rewriting constants from C compiled code.
 */

#include "common.h"

struct map map_val __section("maps") = {
	.type        = 1,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 1,
};

const unsigned long long_val;
const unsigned int int_val;
const unsigned short short_val;
const unsigned char char_val;
const unsigned char bool_val;

const unsigned long long_array[0];
const unsigned int int_array[0];
const unsigned short short_array[0];
const unsigned char char_array[0];
const unsigned char bool_array[0];

__section("xdp") int rewrite() {
	unsigned long acc = 0;
	acc |= long_val;
	acc |= int_val;
	acc |= short_val;
	acc |= char_val;
	acc |= bool_val;
	acc |= long_array[1] << 5;
	acc |= int_array[1] << 5;
	acc |= short_array[1] << 5;
	acc |= char_array[1] << 5;
	acc |= bool_array[1] << 5;
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

__section("xdp/invalid") int invalid_rewrite() {
	unsigned long acc = 0;
	acc |= int_val;
	const char *arr = (const char*)short_array;
	acc |= arr[1];
	acc |= long_array[2];
	return acc;
}
