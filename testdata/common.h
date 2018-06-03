#pragma once

typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

#define __section(NAME) __attribute__((section(NAME), used))

#define BPF_MAP_TYPE_ARRAY (1)
#define BPF_MAP_TYPE_ARRAY_OF_MAPS (12)
#define BPF_MAP_TYPE_HASH_OF_MAPS (13)

#define BPF_F_NO_PREALLOC (1U << 0)

char __license[] __section("license") = "MIT";

struct map {
	uint32_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t flags;
	uint32_t inner_map_idx;
};

static void* (*map_lookup_elem)(const void *map, const void *key) = (void*)1;
