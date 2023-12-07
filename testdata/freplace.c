// /* This file excercises freplace. */

#include "common.h"

char __license[] __section("license") = "MIT";

struct bpf_args {
	uint64_t args[0];
};

__attribute__((noinline)) int subprog() {
	volatile int ret = 0;
	return ret;
}

__section("raw_tracepoint/sched_process_exec") int sched_process_exec(struct bpf_args *ctx) {
	return subprog();
}

__section("freplace/subprog") int replacement() {
	return 0;
}
