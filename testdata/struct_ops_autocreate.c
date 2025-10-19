#include "common.h"

char _license[] __section("license") = "GPL";

struct bpf_testmod_ops {
	int (*test_1)(void);
	int data;
};

__section("struct_ops/test_1") int foo(void) {
	return 0;
}

__section("struct_ops/test_1") int bar(void) {
	return 0;
}

__section(".struct_ops.link") struct bpf_testmod_ops testmod_ops = {
	.test_1 = (void *)foo,
};
