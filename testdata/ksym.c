#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, uint32_t);
	__type(value, uint64_t);
} array_map __section(".maps");

// Non-weak ksyms must be present in the kernel.
extern void bpf_init __ksym;
// Weak ksyms are potentially zero at runtime.
extern void bpf_trace_run1 __ksym __weak;

__section("socket") int ksym_test() {
	uint32_t i;
	uint64_t val;

	i   = 0;
	val = (uint64_t)&bpf_init;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	i   = 1;
	val = (uint64_t)&bpf_trace_run1;
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

struct softnet_data__local {
	unsigned int processed;
} __attribute__((preserve_access_index));

extern const int bpf_prog_active __ksym __weak;
extern const struct softnet_data__local softnet_data __ksym __weak;

uint64_t out__bpf_prog_active_addr;
uint64_t out__softnet_data_addr;

__section("socket") int typed_ksym_test() {
	out__bpf_prog_active_addr = (uint64_t)&bpf_prog_active;
	out__softnet_data_addr    = (uint64_t)&softnet_data;
	return 0;
}

extern const int bpf_testmod_ksym_percpu __ksym __weak;

uint64_t out__bpf_testmod_ksym_percpu_addr;

__section("socket") int typed_ksym_mod_var_test() {
	out__bpf_testmod_ksym_percpu_addr = (uint64_t)&bpf_testmod_ksym_percpu;
	return 0;
}
