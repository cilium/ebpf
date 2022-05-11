#include "../../testdata/common.h"
#include "bpf_core_read.h"

#define core_access __builtin_preserve_access_index

// Struct with the members declared in the wrong order. Accesses need
// a successful CO-RE relocation against the type in relocs_read_tgt.c
// for the test below to pass.
struct s {
	char b;
	char a;
};

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

// Struct with bitfields.
struct bits {
	int x;
	u8 a : 4, b : 2;
	u16 c : 1;
	unsigned int d : 2;
	enum { ZERO = 0, ONE = 1 } e : 1;
	u64 f : 16, g : 30;
};

struct nonexist {
	int non_exist;
};

enum nonexist_enum { NON_EXIST = 1 };

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

	struct bits bar;
	char *p = (char *)&bar;
	/* Target:
	 * [4] STRUCT 'bits' size=8 vlen=7
	 * 'b' type_id=5 bits_offset=0 bitfield_size=2
	 * 'a' type_id=5 bits_offset=2 bitfield_size=4
	 * 'd' type_id=7 bits_offset=6 bitfield_size=2
	 * 'c' type_id=9 bits_offset=8 bitfield_size=1
	 * 'e' type_id=11 bits_offset=9 bitfield_size=1
	 * 'f' type_id=9 bits_offset=16
	 * 'g' type_id=12 bits_offset=32 bitfield_size=30
	 */
	*p++ = 0xff; // a, b, d
	*p++ = 0x00; // c, e
	*p++ = 0x56; // f
	*p++ = 0x56; // f
#ifdef __BIG_ENDIAN__
	*p++ = 0x55; // g
	*p++ = 0x44; // g
	*p++ = 0x33; // g
	*p++ = 0x22; // g
#else
	*p++ = 0x22; // g
	*p++ = 0x33; // g
	*p++ = 0x44; // g
	*p++ = 0x55; // g
#endif

	if (BPF_CORE_READ_BITFIELD(&bar, a) != (1 << 4) - 1)
		return __LINE__;

	if (BPF_CORE_READ_BITFIELD(&bar, b) != (1 << 2) - 1)
		return __LINE__;

	if (BPF_CORE_READ_BITFIELD(&bar, d) != (1 << 2) - 1)
		return __LINE__;

	if (BPF_CORE_READ_BITFIELD(&bar, c) != 0)
		return __LINE__;

	if (BPF_CORE_READ_BITFIELD(&bar, e) != 0)
		return __LINE__;

	if (BPF_CORE_READ_BITFIELD(&bar, f) != 0x5656)
		return __LINE__;

	if (BPF_CORE_READ_BITFIELD(&bar, g) != 0x15443322)
		return __LINE__;

	if (bpf_core_type_exists(struct nonexist) != 0)
		return __LINE__;

	if (bpf_core_field_exists(((struct nonexist *)0)->non_exist) != 0)
		return __LINE__;

	if (bpf_core_enum_value_exists(enum nonexist_enum, NON_EXIST) != 0)
		return __LINE__;

	return 0;
}

__section("socket") int reads() {
	int ret = read_subprog();
	if (ret)
		return ret;

	return 0;
}
