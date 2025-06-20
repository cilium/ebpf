/* This file is used for benchmarking LoadAndAssign().
 */

#include "../btf/testdata/bpf_core_read.h"
#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

__section("kprobe/__scm_send") int __scm_send() {
	return 0;
}
