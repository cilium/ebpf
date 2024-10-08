#include "common.h"

char __license[] __section("license") = "MIT";

typedef char custkey[48];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, custkey);
	__type(value, uint32_t);
} my_map __section(".maps");

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
