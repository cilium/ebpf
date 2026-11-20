//go:build ignore

// maps_declare {
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// A hash map called 'packets', keyed by a 32-bit identifier and holding a
// 64-bit counter per key. The __uint, __type and SEC macros are provided by
// libbpf's bpf_helpers.h.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} packets SEC(".maps");
// }

// maps_legacy {
struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

struct bpf_map_def legacy_packets SEC("maps") = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1024,
};
// }

// maps_program {
SEC("socket") int count_packet(__u32 key) {
	__u64 *count = bpf_map_lookup_elem(&packets, &key);
	if (count)
		__sync_fetch_and_add(count, 1);

	return 0;
}
// }