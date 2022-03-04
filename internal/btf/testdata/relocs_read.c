#include "../../../testdata/common.h"

#define core_access __builtin_preserve_access_index

// Struct with the members declared in the wrong order. Accesses need
// a successful CO-RE relocation against the type in relocs_read_tgt.c
// for the test below to pass.
struct s {
	char b;
	char a;
};

// Perform a read from a subprog to ensure CO-RE relocations
// occurring there are tracked and executed in the final linked program.
__attribute__((noinline)) int read_subprog() {
	struct s foo = {
		.a = 0,
		.b = 1,
	};

	if (core_access(foo.a) == 0)
		return __LINE__;

  if (core_access(foo.b) == 1)
    return __LINE__;

	return 0;
}

__section("socket") int reads() {
	int ret = read_subprog();
	if (ret)
		return ret;

	return 0;
}

