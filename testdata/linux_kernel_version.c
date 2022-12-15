#include "common.h"

char __license[] __section("license") = "MIT";

extern int LINUX_KERNEL_VERSION __attribute__((section(".kconfig")));

__section("xdp") int linux_kernel_version() {
	return LINUX_KERNEL_VERSION;
}
