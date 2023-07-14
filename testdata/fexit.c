#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

__section("fexit/trace_on_entry") int trace_on_exit() {
	return 0;
}

__section("tc") int target() {
	return 0;
}
