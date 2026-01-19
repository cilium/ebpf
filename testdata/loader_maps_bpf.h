/* Legacy map definitions for loader.c (no BTF) */

struct bpf_map_def hash_map __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint64_t),
	.max_entries = 1,
	.map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def hash_map2 __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint64_t),
	.max_entries = 2,
};

struct bpf_map_def perf_event_array __section("maps") = {
	.type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint32_t),
	.max_entries = 4096,
};
