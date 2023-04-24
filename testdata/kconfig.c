#include "common.h"

char __license[] __section("license") = "MIT";

extern int LINUX_KERNEL_VERSION __kconfig;
extern int LINUX_HAS_SYSCALL_WRAPPER __kconfig;

__section("socket") int kernel_version() {
	return LINUX_KERNEL_VERSION;
}

__section("socket") int syscall_wrapper() {
	return LINUX_HAS_SYSCALL_WRAPPER;
}
