#include "common.h"

char __license[] __section("license") = "MIT";

// Highly inspired from libbpf test:
// https://github.com/torvalds/linux/blob/6e98b09da931a00bf4e0477d0fa52748bf28fcce/tools/testing/selftests/bpf/progs/test_core_extern.c
// The modifications are the following:
// 1. Removed __weak as cilium/ebpf does not support it.
// 2. Removed CONFIG_BPF_SYSCALL as we cannot be sure it will be found.
// 3. Removed call to bpf_missing_helper() as we do not have it.
// 4. Used an array bpf map to store the value rather than the .data map.
extern enum libbpf_tristate CONFIG_TRISTATE __kconfig;
extern bool CONFIG_BOOL __kconfig;
extern char CONFIG_CHAR __kconfig;
extern uint16_t CONFIG_USHORT __kconfig;
extern int CONFIG_INT __kconfig;
extern uint64_t CONFIG_ULONG __kconfig;
extern const char CONFIG_STR[8] __kconfig;
extern uint64_t CONFIG_MISSING __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, uint32_t);
	__type(value, uint64_t);
} array_map __section(".maps");

static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, uint64_t flags) = (void *)2;

__section("socket") int kconfig() {
	uint32_t i;
	uint64_t val;

	i   = 0;
	val = CONFIG_TRISTATE;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	i   = 1;
	val = CONFIG_BOOL;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	i   = 2;
	val = CONFIG_CHAR;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	i   = 3;
	val = CONFIG_USHORT;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	i   = 4;
	val = CONFIG_INT;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	i   = 5;
	val = CONFIG_ULONG;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	char str[8];
	for (i = 0; i < sizeof(CONFIG_STR); i++) {
		str[i] = CONFIG_STR[i];
	}

	i = 6;
	__builtin_mempcpy(&val, str, sizeof val);
	bpf_map_update_elem(&array_map, &i, &val, 0);

	i = 7;
	if (!CONFIG_MISSING)
		val = 0xCAFEC0DE;
	bpf_map_update_elem(&array_map, &i, &val, 0);

	return 0;
}
