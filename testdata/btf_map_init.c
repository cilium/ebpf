/* This file excercises the ELF loader. It is not a valid BPF program. */

#include "common.h"

#if __clang_major__ >= 9

int __section("socket/tail") tail_1() {
	return 42;
}

// Tail call map (program array) initialized with program pointers.
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(max_entries, 2);
	__array(values, int ());
} prog_array_init __section(".maps") = {
	.values = {
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

#else
#error This file has to be compiled with clang >= 9
#endif
