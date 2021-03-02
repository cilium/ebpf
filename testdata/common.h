#pragma once

typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

#define __section(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH (1)
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY (4)
#define BPF_MAP_TYPE_ARRAY_OF_MAPS (12)
#define BPF_MAP_TYPE_HASH_OF_MAPS (13)

#define BPF_F_NO_PREALLOC (1U << 0)
#define BPF_F_CURRENT_CPU (0xffffffffULL)

/* From tools/lib/bpf/libbpf.h */
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

static void *(*map_lookup_elem)(const void *map, const void *key) = (void *)1;

static long (*trace_printk)(const char *fmt, uint32_t fmt_size, ...) = (void *)6;

static int (*perf_event_output)(const void *ctx, const void *map, uint64_t index, const void *data, uint64_t size) = (void *)25;

static uint32_t (*get_smp_processor_id)(void) = (void *)8;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, uint64_t flags) = (void *) 2;

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
	BPF_F_LOCK = 4,
};
