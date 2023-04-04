#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

extern void bpf_testmod_test_mod_kfunc(int) __ksym;
extern void bpf_kfunc_call_test_mem_len_pass1(void *mem, int len) __ksym;

__section("tc") int call_kmod_kfunc() {
    bpf_testmod_test_mod_kfunc(0);
    bpf_kfunc_call_test_mem_len_pass1((void *)0, 0);
	return 1;
}
