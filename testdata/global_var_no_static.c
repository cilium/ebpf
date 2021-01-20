#include "common.h"

volatile int FOO;

char __license[] __section("license") = "MIT";

__section("socket")
int filter(void *ctx) {
	return FOO;
}
