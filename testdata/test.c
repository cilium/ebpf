/* This file excercises the ELF loader. It is not a valid BPF program.
 */

typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

#define __section(NAME) __attribute__((section(NAME), used))

#define BPF_MAP_TYPE_ARRAY_OF_MAPS (12)
#define BPF_MAP_TYPE_HASH_OF_MAPS (13)

char __license[] __section("license") = "MIT";

struct map {
	uint32_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t flags;
	uint32_t inner_map_idx;
};

struct map hash_map __section("maps") = {
	.type = 1,
	.key_size = 4,
	.value_size = 2,
	.max_entries = 42,
	.flags = 4242,
};

struct map hash_map2 __section("maps") = {
	.type = 1,
	.key_size = 2,
	.value_size = 1,
	.max_entries = 21,
	.flags = 2121,
};

struct map array_of_hash_map __section("maps") = {
	.type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.key_size = sizeof(uint32_t),
	.max_entries = 2,
	.inner_map_idx = 0, // points to "hash_map"
};

struct map hash_of_hash_map __section("maps") = {
	.type = BPF_MAP_TYPE_HASH_OF_MAPS,
	.key_size = sizeof(uint32_t),
	.max_entries = 2,
	.inner_map_idx = 1, // points to "hash_map2"
};

unsigned long non_map;

static void (*map_lookup_elem)(void *) = (void*)1;
static void (*other_fn)(unsigned long) = (void*)2;

int __attribute__((noinline)) helper_func(int arg) {
	return arg > 5;
}

__section("xdp") int xdp_prog() {
	map_lookup_elem(&hash_map);
	map_lookup_elem(&hash_map2);
	other_fn(non_map);
	return helper_func(2);
}

// This function has no relocations, and is thus parsed differently.
__section("socket") int no_relocation() {
	return 0;
}
