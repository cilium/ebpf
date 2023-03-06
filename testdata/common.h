#pragma once

typedef _Bool bool;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

enum libbpf_tristate {
	TRI_NO = 0,
	TRI_YES = 1,
	TRI_MODULE = 2,
};

#define __section(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define __kconfig __attribute__((section(".kconfig")))
#define __ksym __attribute__((section(".ksyms")))

#define BPF_MAP_TYPE_HASH (1)
#define BPF_MAP_TYPE_ARRAY (2)
#define BPF_MAP_TYPE_PROG_ARRAY (3)
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

static long (*map_update_elem)(const void *map, const void *key, const void *value, uint64_t flags) = (void *)2;

static long (*trace_printk)(const char *fmt, uint32_t fmt_size, ...) = (void *)6;

static long (*tail_call)(void *ctx, void *prog_array_map, uint32_t index) = (void *)12;

static int (*perf_event_output)(const void *ctx, const void *map, uint64_t index, const void *data, uint64_t size) = (void *)25;

static uint32_t (*get_smp_processor_id)(void) = (void *)8;

static long (*for_each_map_elem)(const void *map, void *callback_fn, void *callback_ctx, uint64_t flags) = (void *)164;
