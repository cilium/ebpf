typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

#define __section(NAME) __attribute__((section(NAME), used))

char __license[] __section("license") = "MIT";

struct map {
	uint32_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t flags;
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

static void (*map_lookup_elem)(void *) = (void*)1;

__section("xdp") int xdp_prog() {
	map_lookup_elem(&hash_map);
	map_lookup_elem(&hash_map2);
	return 0;
}

// This function has no relocations, and is thus parsed differently.
__section("socket") int no_relocation() {
	return 0;
}
