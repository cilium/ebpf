/* This file excercises the ELF loader. */

#include "common.h"

char __license[] __section("license") = "MIT";

struct bpf_args {
	uint64_t args[0];
};

__section("raw_tracepoint/sched_process_exec") int sched_process_exec(struct bpf_args *ctx) {
	return 0;
}
