#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

extern void bpf_testmod_test_mod_kfunc(int) __ksym;

__section("tc") int call_kfunc() {
	bpf_testmod_test_mod_kfunc(0);
	return 1;
}
