#include "common.h"
#include "../btf/testdata/bpf_core_read.h"

struct nonexist {
	int non_exist;
};

enum nonexist_enum { NON_EXIST = 1 };

__section("socket") int poisoned_single() {
	struct nonexist ne;
	return core_access(ne.non_exist);
}

__section("socket") int poisoned_double() {
	return bpf_core_enum_value(enum nonexist_enum, NON_EXIST);
}

extern int invalid_kfunc(void) __ksym __weak;

__section("socket") int poisoned_kfunc() {
	// NB: This doesn't go via CO-RE but uses a similar mechanism to generate
	// an invalid instruction. We test it here for convenience.
	return invalid_kfunc();
}
