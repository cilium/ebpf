#include "common.h"

char __license[] __section("license") = "GPL-2.0";

extern int CONFIG_HZ __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, uint32_t);
	__type(value, uint64_t);
} array_map __section(".maps");

__section("socket") int kconfig() {
	uint32_t i;
	uint64_t val;

	i   = 0;
	val = CONFIG_HZ;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	return 0;
}
