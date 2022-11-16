/* This file excercises the ELF loader. It is not a valid BPF program. */

#include "common.h"

#if __clang_major__ >= 9

int __section("socket/tail") tail_1() {
	return 42;
}

// Tail call map (program array) initialized with program pointers.
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 2);
	__array(values, int());
} prog_array_init __section(".maps") = {
	.values =
		{
			// Skip index 0 to exercise empty array slots.
			[1] = &tail_1,
		},
};

int __section("socket/main") tail_main(void *ctx) {
	// If prog_array_init is correctly populated, the tail call
	// will succeed and the program will continue in tail_1 and
	// not return here.
	tail_call(ctx, &prog_array_init, 1);

	return 0;
}

// Inner map with a single possible entry.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, uint32_t);
} inner_map __section(".maps");

// Outer map carrying a reference to the inner map.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 2);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__array(values, typeof(inner_map));
} outer_map_init __section(".maps") = {
	.values =
		{
			// Skip index 0 to exercise empty array slots.
			[1] = &inner_map,
		},
};

#else
#error This file has to be compiled with clang >= 9
#endif
