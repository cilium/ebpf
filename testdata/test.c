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

static void (*map_lookup_elem)(void *) = (void*)1;

__section("xdp") int xdp_prog() {
	map_lookup_elem(&hash_map);
	return 0;
}
