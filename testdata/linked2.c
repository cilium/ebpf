#include "common.h"
#include "linked.h"

// Weak in L1, strong in L2.
__section(".maps") struct h32_btf map_l1_w;

// Strong in L1, weak in L2.
__weak __section(".maps") struct h32_btf map_l1_s;

// Weak in both L1 and L2.
__weak __section(".maps") struct h32_btf map_ww;

// Strong in L2, only defined here.
__section(".maps") struct h32_btf map_l2;

// Strong in L1, weak in L2.
__weak __section("maps") struct bpf_map_def map_legacy_l1_s = h32_legacy(__LINE__);

// Weak in L1, strong in L2.
__section("maps") struct bpf_map_def map_legacy_l2_s = h32_legacy(1);

// Call external symbol only defined in L1.
extern int l1(void);
__section("socket") int entry_l1() {
	return l1();
}

// Weak and only defined in L2, called extern in L1.
__weak __noinline int l2() {
	return 0;
}

// Weak in L1, strong in L2.
__noinline int l1_w() {
	return 0;
}
__section("socket") int entry_l1_w() {
	return l1_w();
}

// Strong in L1, weak in L2.
__weak __noinline int l1_s() {
	return __LINE__;
}
__weak __section("socket") int entry_l1_s() {
	return l1_s();
}

// Weak in both L1 and L2.
__weak __noinline int ww() {
	return __LINE__;
}
__weak __section("socket") int entry_ww() {
	return ww();
}
