//go:build ignore

// DocMyMapProgram {
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Declare a hash map called 'my_map' with a u32 key and a u64 value.
// The __uint, __type and SEC macros are from libbpf's bpf_helpers.h.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} my_map SEC(".maps");

// Declare a dummy socket program called 'my_prog'.
SEC("socket") int my_prog() {
	return 0;
}
// }
