#include "common.h"

struct bpf_dummy_ops {
	int (*test_1)(void *);
	int (*test_2)(void *, int, short unsigned int, char, long unsigned int);
	int (*test_sleepable)(void *);
};

char __license[] __section("license") = "Dual MIT/GPL";

__section("struct_ops/dummy_test_1") int dummy_test_1(void *arg) {
	return 0;
}

__section("struct_ops.s/dummy_test_sleepable") int dummy_test_sleepable(void *arg) {
	return 0;
}

__section(".struct_ops.link") struct bpf_dummy_ops dummy_ops = {.test_1 = dummy_test_1, .test_sleepable = dummy_test_sleepable};
