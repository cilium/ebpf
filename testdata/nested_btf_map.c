/* This file excercises the ELF loader. It is not a valid BPF program.
 */

#include "common.h"

char __license[] __section("license") = "MIT";

// Typedef, doesn't automatically get an ELF symbol.
struct inner_map_t {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, int);
	__uint(max_entries, 1);
};

// Named map definition with anonymous type definition.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(uint32_t));
	__uint(max_entries, 1);
	__uint(values, sizeof(struct inner_map_t));
} outer_map __section(".maps");

// Array of maps with anonymous inner struct.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(uint32_t));
	__uint(max_entries, 1);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_HASH);
		__uint(max_entries, 1);
		__type(key, uint32_t);
		__type(value, uint32_t);
	});
} outer_map_anon __section(".maps");
