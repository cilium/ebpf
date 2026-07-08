#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

// Non-weak ksyms must be present in the kernel.
extern void bpf_init __ksym;
// Weak ksyms are potentially zero at runtime.
extern void bpf_trace_run1 __ksym __weak;

uint64_t out__bpf_init_addr;
uint64_t out__bpf_trace_run1_addr;

__section("socket") int ksym_test() {
	out__bpf_init_addr       = (uint64_t)&bpf_init;
	out__bpf_trace_run1_addr = (uint64_t)&bpf_trace_run1;
	return 0;
}

extern void missing_ksym __ksym;
extern void missing_weak_ksym __ksym __weak;

__section("socket") int missing_ksym_test() {
	return (uint64_t)&missing_ksym;
}

__section("socket") int missing_weak_ksym_test() {
	if (&missing_weak_ksym != 0) {
		return __LINE__;
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

extern const int missing_typed_ksym __ksym;
extern const int missing_weak_typed_ksym __ksym __weak;

__section("socket") uint64_t missing_typed_ksym_test() {
	return (uint64_t)&missing_typed_ksym;
}

__section("socket") int missing_weak_typed_ksym_test() {
	if (&missing_weak_typed_ksym != 0) {
		return __LINE__;
	}
	return 0;
}
