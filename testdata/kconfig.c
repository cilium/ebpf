#include "common.h"

char __license[] __section("license") = "MIT";

extern int LINUX_KERNEL_VERSION __kconfig;
extern int LINUX_EXTRA_CONFIG __kconfig;

__section("socket") int kconfig() {
	return LINUX_KERNEL_VERSION;
}

__section("socket") int extra() {
	return LINUX_EXTRA_CONFIG;
}
