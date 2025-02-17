#include "common.h"
#include "../btf/testdata/bpf_core_read.h"

struct nonexist {
	int non_exist;
};

enum nonexist_enum { NON_EXIST = 1 };

// Force loading program with BTF by including a relocation for a local type.
#define FORCE_BTF \
	do { \
		if (bpf_core_type_id_local(int) == 0) \
			return __LINE__; \
	} while (0)

__section("socket") int poisoned_single() {
	FORCE_BTF;
	struct nonexist ne;
	return core_access(ne.non_exist);
}

__section("socket") int poisoned_double() {
	FORCE_BTF;
	return bpf_core_enum_value(enum nonexist_enum, NON_EXIST);
}

extern int invalid_kfunc(void) __ksym __weak;

__section("socket") int poisoned_kfunc() {
	// NB: This doesn't go via CO-RE but uses a similar mechanism to generate
	// an invalid instruction. We test it here for convenience.
	return invalid_kfunc();
}
