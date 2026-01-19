/* BTF-style map definitions for loader.c */

#pragma once

#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint64_t);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} hash_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint64_t));
	__uint(max_entries, 2);
} hash_map2 __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint64_t);
	__uint(max_entries, 1);
	__uint(pinning, 1 /* LIBBPF_PIN_BY_NAME */);
} btf_pin __section(".maps");

// Named map type definition, without structure variable declaration.
struct inner_map_t {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, int);
	__uint(max_entries, 1);
};

// Anonymous map type definition with structure variable declaration.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(uint32_t));
	__uint(max_entries, 1);
	__array(values, struct inner_map_t);
} btf_outer_map __section(".maps");

// Array of maps with anonymous inner struct.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(uint32_t));
	__uint(max_entries, 1);
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, uint32_t);
			__type(value, uint32_t);
		});
} btf_outer_map_anon __section(".maps");

struct perf_event {
	uint64_t foo;
	uint64_t bar;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 4096);
	__type(value, struct perf_event);
} perf_event_array __section(".maps");

typedef struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint64_t));
	__uint(max_entries, 1);
} array_map_t;

// Map definition behind a typedef.
array_map_t btf_typedef_map __section(".maps");

#define __decl_tags __attribute__((btf_decl_tag("a"), btf_decl_tag("b")))

// Legacy map definition decorated with decl tags.
struct bpf_map_def bpf_decl_map __decl_tags __section("maps") = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint64_t),
	.max_entries = 1,
};

// BTF map definition decorated with decl tags.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint64_t));
	__uint(max_entries, 1);
} btf_decl_map __decl_tags __section(".maps");
