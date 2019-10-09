#pragma once

typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

#define __section(NAME) __attribute__((section(NAME), used))

#define BPF_MAP_TYPE_ARRAY (1)
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY (4)
#define BPF_MAP_TYPE_ARRAY_OF_MAPS (12)
#define BPF_MAP_TYPE_HASH_OF_MAPS (13)

#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_F_CURRENT_CPU (0xffffffffULL)

struct map {
	uint32_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t flags;
	uint32_t inner_map_idx;
	uint32_t dummy;
};

static void* (*map_lookup_elem)(const void *map, const void *key) = (void*)1;
static int (*perf_event_output)(const void *ctx, const void *map, uint64_t index, const void *data, uint64_t size) = (void*)25;
static uint32_t (*get_smp_processor_id)(void) = (void*)8;
