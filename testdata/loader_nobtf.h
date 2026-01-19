/* Legacy map definitions for loader.c (no BTF) */

#pragma once

#include "common.h"

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

// key_size and value_size always need to be 4 bytes and are automatically set
// when the map is created if left at 0 in the ELF. Leave them at 0 for
// consistency with the BTF map definitions, which specify key and value types,
// causing sizes to be 0 in the MapSpec. This avoids special casing in tests.
struct bpf_map_def perf_event_array __section("maps") = {
	.type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.max_entries = 4096,
};
