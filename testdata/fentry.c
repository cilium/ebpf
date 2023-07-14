#include "common.h"

char __license[] __section("license") = "Dual MIT/GPL";

__section("fentry/trace_on_entry") int trace_on_entry() {
	return 0;
}

__section("tc") int target() {
	return 0;
}
