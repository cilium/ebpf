/* This file is used for benchmarking LoadAndAssign().
 */

#include "../btf/testdata/bpf_core_read.h"
#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

__section("kprobe/fsnotify_remove_first_event") int fsnotify_remove_first_event() {
	return 0;
}
