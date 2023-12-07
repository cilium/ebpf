#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

// This function declaration is incorrect on purpose.
extern void bpf_kfunc_call_test_mem_len_pass1(void) __ksym;

__section("tc") int call_kfunc() {
	bpf_kfunc_call_test_mem_len_pass1();
	return 1;
}
