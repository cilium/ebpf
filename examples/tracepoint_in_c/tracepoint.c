//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") counting_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/kmem/mm_page_alloc/format
struct alloc_info {
	/* The first 8 bytes is not allowed to read */
	unsigned long pad;

	unsigned long pfn;
	unsigned int order;
	unsigned int gfp_flags;
	int migratetype;
};

// This tracepoint is defined in mm/page_alloc.c:__alloc_pages_nodemask()
// Userspace pathname: /sys/kernel/tracing/events/kmem/mm_page_alloc
SEC("tracepoint/kmem/mm_page_alloc")
int mm_page_alloc(struct alloc_info *info) {
	u32 key     = 0;
	u64 initval = 1, *valp;

	valp = bpf_map_lookup_elem(&counting_map, &key);
	if (!valp) {
		bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);
	return 0;
}
