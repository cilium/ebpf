#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, uint32_t);
	__type(value, uint64_t);
} array_map __section(".maps");

extern void socket_file_ops __ksym;
extern void tty_fops __ksym __weak;

__section("socket") int ksym_test() {
	uint32_t i;
	uint64_t val;

	i   = 0;
	val = (uint64_t)&socket_file_ops;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	i   = 1;
	val = (uint64_t)&tty_fops;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	return 0;
}

extern void non_existing_symbol __ksym __weak;

__section("socket") int ksym_missing_test() {
	if (&non_existing_symbol == 0) {
		return 1;
	}
	return 0;
}
