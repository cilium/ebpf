#include "common.h"

// Weak in L1, strong in L2
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} map_l1w __weak __section(".maps");

// Strong in L1, weak in L2
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} map_l1s __section(".maps");

// Defined in both as weak
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} map_ww __weak __section(".maps");

// Defined in L1 only as strong
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} map_l1os __section(".maps");

// Legacy map, strong in L1, weak in L2
struct bpf_map_def map_legacy_l1s __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(int),
	.value_size  = sizeof(int),
	.max_entries = 100,
	.map_flags   = BPF_F_NO_PREALLOC,
};

// Legacy map, weak in L1, strong in L2
struct bpf_map_def map_legacy_l2s __weak __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(int),
	.value_size  = sizeof(int),
	.max_entries = 100,
	.map_flags   = BPF_F_NO_PREALLOC,
};

// Weak in L1, strong in L2
__attribute__((noinline)) __weak int fun_l1w() {
	return 1;
}

// Strong in L1, weak in L2
__attribute__((noinline)) int fun_l1s() {
	return 2;
}

// Defined weak in both
__attribute__((noinline)) __weak int fun_ww() {
	return 3;
}

// Defined in L1 only as strong
__attribute__((noinline)) int fun_l1os() {
	return 4;
}

// Defined in L1 only as weak
__attribute__((noinline)) __weak int fun_l1ow() {
	return 5;
}

// Externally defined in L2
extern int fun_l2os(void);

// Weak in L1, strong in L2
__section("socket") __weak int entrypoint_l1w() {
	return fun_l1w();
}

// Strong in L1, weak in L2
__section("socket") int entrypoint_l1s() {
	return fun_l1s();
}

// Defined in both as weak
__section("socket") __weak int entrypoint_ww() {
	return fun_ww();
}

// Defined in L1 only as strong
__section("socket") int entrypoint_l1os() {
	return fun_l2os();
}

// Defined in L1 only as weak
__section("socket") __weak int entrypoint_l1ow() {
	return fun_l1ow();
}
