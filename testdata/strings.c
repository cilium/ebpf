#include "common.h"

char __license[] __section("license") = "MIT";

typedef char custkey[48];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, custkey);
	__type(value, uint32_t);
} my_map __section(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key)                                   = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, uint64_t flags) = (void *)2;

#define KEY "This string is allocated in the string section\n"

__section("xdp") int filter() {
	uint32_t *value = bpf_map_lookup_elem(&my_map, KEY);
	if (value)
		(*value)++;
	else {
		uint32_t newValue = 1;
		bpf_map_update_elem(&my_map, KEY, &newValue, 0);
	}

	return 2;
}
