#include "common.h"

char __license[] __section("license") = "GPL-2.0";

/* Special cases requiring feature testing or vDSO magic. */
extern int LINUX_KERNEL_VERSION __kconfig;
extern _Bool LINUX_HAS_SYSCALL_WRAPPER __kconfig;

/* Values pulled from /proc/kconfig. */
extern int CONFIG_HZ __kconfig;
extern enum libbpf_tristate CONFIG_BPF_SYSCALL __kconfig;
extern char CONFIG_DEFAULT_HOSTNAME[1] __kconfig;

__section("socket") int kconfig() {
	if (LINUX_KERNEL_VERSION == 0)
		return __LINE__;

	if (LINUX_HAS_SYSCALL_WRAPPER == 0)
		return __LINE__;

	if (CONFIG_HZ == 0)
		return __LINE__;

	if (CONFIG_BPF_SYSCALL == TRI_NO)
		return __LINE__;

	if (CONFIG_DEFAULT_HOSTNAME[0] == 0)
		return __LINE__;

	return 0;
}
