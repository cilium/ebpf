/* This file excercises the ELF loader.
 */

#include "common.h"

char __license[] __section("license") = "MIT";

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

struct bpf_map_def array_of_hash_map __section("maps") = {
	.type        = BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.key_size    = sizeof(uint32_t),
	.max_entries = 2,
};

typedef struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint64_t));
	__uint(max_entries, 1);
} array_map_t;

// Map definition behind a typedef.
array_map_t btf_typedef_map __section(".maps");

static int __attribute__((noinline)) __section("static") static_fn(uint32_t arg) {
	return arg - 1;
}

int __attribute__((noinline)) global_fn2(uint32_t arg) {
	return arg + 2;
}

int __attribute__((noinline)) __section("other") global_fn3(uint32_t arg) {
	return arg + 1;
}

int __attribute__((noinline)) global_fn(uint32_t arg) {
	return static_fn(arg) + global_fn2(arg) + global_fn3(arg);
}

volatile unsigned int key1       = 0; // .bss
volatile unsigned int key2       = 1; // .data
volatile const unsigned int key3 = 2; // .rodata

// .rodata, populated by loader
volatile const uint32_t arg;
// custom .rodata section, populated by loader
volatile const uint32_t arg2 __section(".rodata.test");
// custom .data section
volatile uint32_t arg3 __section(".data.test");

__section("xdp") int xdp_prog() {
	bpf_map_lookup_elem(&hash_map, (void *)&key1);
	bpf_map_lookup_elem(&hash_map2, (void *)&key2);
	bpf_map_lookup_elem(&hash_map2, (void *)&key3);
	return static_fn(arg) + global_fn(arg) + arg2 + arg3;
}

// This function has no relocations, and is thus parsed differently.
__section("socket") int no_relocation() {
	return 0;
}

// Make sure we allow relocations generated by inline assembly.
__section("socket/2") int asm_relocation() {
	int my_const;
	asm("%0 = MY_CONST ll" : "=r"(my_const));
	return my_const;
}

volatile const unsigned int uneg               = -1;
volatile const int neg                         = -2;
static volatile const unsigned int static_uneg = -3;
static volatile const int static_neg           = -4;

__section("socket/3") int data_sections() {
	if (uneg != (unsigned int)-1)
		return __LINE__;

	if (neg != -2)
		return __LINE__;

	if (static_uneg != (unsigned int)-3)
		return __LINE__;

	if (static_neg != -4)
		return __LINE__;

	return 0;
}

/*
 * Up until LLVM 14, this program results in an .rodata.cst32 section
 * that is accessed by 'return values[i]'. For this section, no BTF is
 * emitted. 'values' cannot be rewritten, since there is no BTF info
 * describing the data section.
 */
__section("socket/4") int anon_const() {
	volatile int ctx = 0;

// 32 bytes wide results in a .rodata.cst32 section.
#define values \
	(uint64_t[]) { \
		0x0, 0x1, 0x2, 0x3 \
	}

	int i;
	for (i = 0; i < 3; i++) {
		if (ctx == values[i]) {
			return values[i];
		}
	}

	return 0;
}
