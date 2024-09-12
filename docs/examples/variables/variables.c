//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Remove when toolchain Docker image ships with 5.13+ headers.
#define __hidden __attribute__((visibility("hidden")))

// variables_const {
volatile const __u32 const_u32;

SEC("socket") int const_example() {
	return const_u32;
}
// }

// variables_global {
volatile __u16 global_u16;

SEC("socket") int global_example() {
	global_u16++;
	return global_u16;
}
// }

// variables_hidden {
__hidden __u64 hidden_var;

SEC("socket") int hidden_example() {
	hidden_var++;
	return hidden_var;
}
// }
