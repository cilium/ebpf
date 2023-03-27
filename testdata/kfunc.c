#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

extern void bpf_kfunc_call_test_mem_len_pass1(void *mem, int len) __ksym;

__section("tc") int call_kfunc() {
	bpf_kfunc_call_test_mem_len_pass1((void *)0, 0);
	return 1;
}
