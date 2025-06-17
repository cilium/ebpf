/* This file is used for benchmarking LoadAndAssign().
 */

#include "../btf/testdata/bpf_core_read.h"
#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

__section("kprobe/tcp_connect") int tcp_connect() {
	return 0;
}
