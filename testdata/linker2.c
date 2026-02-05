#include "common.h"

// Weak in L1, strong in L2
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} map_l1w __section(".maps");

// Strong in L1, weak in L2
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} map_l1s __weak __section(".maps");

// Defined in both as weak
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} map_ww __weak __section(".maps");

// Defined in L2 only as strong
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} map_l2os __section(".maps");

// Legacy map, strong in L1, weak in L2
struct bpf_map_def map_legacy_l1s __weak __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(int),
	.value_size  = sizeof(int),
	.max_entries = 100,
	.map_flags   = BPF_F_NO_PREALLOC,
};

// Legacy map, weak in L1, strong in L2
struct bpf_map_def map_legacy_l2s __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(int),
	.value_size  = sizeof(int),
	.max_entries = 100,
	.map_flags   = BPF_F_NO_PREALLOC,
};

// Weak in L1, strong in L2
__attribute__((noinline)) int fun_l1w() {
	return 6;
}

// Strong in L1, weak in L2
__attribute__((noinline)) __weak int fun_l1s() {
	return 7;
}

// Defined weak in both
__attribute__((noinline)) __weak int fun_ww() {
	return 8;
}

// Defined in L2 only as strong
__attribute__((noinline)) int fun_l2os() {
	return 9;
}

// Defined in L2 only as weak
__attribute__((noinline)) __weak int fun_l2ow() {
	return 10;
}

// Externally defined in L1
extern int fun_l1os(void);

// Weak in L1, strong in L2
__section("socket") int entrypoint_l1w() {
	return fun_l1w();
}

// Strong in L1, weak in L2
__section("socket") __weak int entrypoint_l1s() {
	return fun_l1s();
}

// Defined in both as weak
__section("socket") __weak int entrypoint_ww() {
	return fun_ww();
}

// Defined in L2 only as strong
__section("socket") int entrypoint_l2os() {
	return fun_l1os();
}

// Defined in L2 only as weak
__section("socket") __weak int entrypoint_l2ow() {
	return fun_l2ow();
}
