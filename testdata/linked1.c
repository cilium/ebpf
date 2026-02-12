#include "common.h"
#include "linked.h"

// Weak in L1, strong in L2.
__weak __section(".maps") struct h32_btf map_l1_w;

// Strong in L1, weak in L2.
__section(".maps") struct h32_btf map_l1_s;

// Weak in both L1 and L2.
__weak __section(".maps") struct h32_btf map_ww;

// Strong in L1, only defined here.
__section(".maps") struct h32_btf map_l1;

// Strong in L1, weak in L2.
__section("maps") struct bpf_map_def map_legacy_l1_s = h32_legacy(1);

// Weak in L1, strong in L2.
__weak __section("maps") struct bpf_map_def map_legacy_l2_s = h32_legacy(__LINE__);

// Call external symbol only defined in L2.
extern int l2(void);
__section("socket") int entry_l2() {
	return l2();
}

// Weak and only defined in L1, called extern in L2.
__weak __noinline int l1() {
	return 0;
}

// Weak in L1, strong in L2.
__weak __noinline int l1_w() {
	return __LINE__;
}
__weak __section("socket") int entry_l1_w() {
	return l1_w();
}

// Strong in L1, weak in L2.
__noinline int l1_s() {
	return 0;
}
__section("socket") int entry_l1_s() {
	return l1_s();
}

// Weak in both L1 and L2.
__weak __noinline int ww() {
	return 0;
}
__weak __section("socket") int entry_ww() {
	return ww();
}
