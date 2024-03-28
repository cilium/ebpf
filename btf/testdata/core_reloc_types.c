#include <stdbool.h>
#include "bpf_core_read.h"

struct a_struct {
	int x;
};

struct a_complex_struct {
	union {
		struct a_struct *restrict a;
		void *b;
	} x;
	volatile long y;
};

union a_union {
	int y;
	int z;
};

typedef struct a_struct named_struct_typedef;

typedef struct {
	int x, y, z;
} anon_struct_typedef;

typedef struct {
	int a, b, c;
} *struct_ptr_typedef;

enum an_enum {
	AN_ENUM_VAL1 = 1,
	AN_ENUM_VAL2 = 2,
	AN_ENUM_VAL3 = 3,
};

typedef int int_typedef;

typedef enum { TYPEDEF_ENUM_VAL1, TYPEDEF_ENUM_VAL2 } enum_typedef;

typedef void *void_ptr_typedef;
typedef int *restrict restrict_ptr_typedef;

typedef int (*func_proto_typedef)(long);

typedef char arr_typedef[20];

struct core_reloc_type_based {
	struct a_struct f1;
	struct a_complex_struct f2;
	union a_union f3;
	enum an_enum f4;
	named_struct_typedef f5;
	anon_struct_typedef f6;
	struct_ptr_typedef f7;
	int_typedef f8;
	enum_typedef f9;
	void_ptr_typedef f10;
	restrict_ptr_typedef f11;
	func_proto_typedef f12;
	arr_typedef f13;
};

/* no types in target */
struct core_reloc_type_based___all_missing {};

/* different member orders, enum variant values, signedness, etc */
struct a_struct___diff {
	int x;
	int a;
};

struct a_struct___forward;

struct a_complex_struct___diff {
	union {
		struct a_struct___forward *a;
		void *b;
	} x;
	volatile long y;
};

union a_union___diff {
	int z;
	int y;
};

typedef struct a_struct___diff named_struct_typedef___diff;

typedef struct {
	int z, x, y;
} anon_struct_typedef___diff;

typedef struct {
	int c;
	int b;
	int a;
} *struct_ptr_typedef___diff;

enum an_enum___diff {
	AN_ENUM_VAL2___diff = 0,
	AN_ENUM_VAL1___diff = 42,
	AN_ENUM_VAL3___diff = 1,
};

typedef unsigned int int_typedef___diff;

typedef enum { TYPEDEF_ENUM_VAL2___diff, TYPEDEF_ENUM_VAL1___diff = 50 } enum_typedef___diff;

typedef const void *void_ptr_typedef___diff;

typedef int_typedef___diff (*func_proto_typedef___diff)(long);

typedef char arr_typedef___diff[3];

struct core_reloc_type_based___diff {
	struct a_struct___diff f1;
	struct a_complex_struct___diff f2;
	union a_union___diff f3;
	enum an_enum___diff f4;
	named_struct_typedef___diff f5;
	anon_struct_typedef___diff f6;
	struct_ptr_typedef___diff f7;
	int_typedef___diff f8;
	enum_typedef___diff f9;
	void_ptr_typedef___diff f10;
	func_proto_typedef___diff f12;
	arr_typedef___diff f13;
};

/* different type sizes, extra modifiers, anon vs named enums, etc */
struct a_struct___diff_sz {
	long x;
	int y;
	char z;
};

union a_union___diff_sz {
	char yy;
	char zz;
};

typedef struct a_struct___diff_sz named_struct_typedef___diff_sz;

typedef struct {
	long xx, yy, zzz;
} anon_struct_typedef___diff_sz;

typedef struct {
	char aa[1], bb[2], cc[3];
} *struct_ptr_typedef___diff_sz;

enum an_enum___diff_sz {
	AN_ENUM_VAL1___diff_sz = 0x123412341234,
	AN_ENUM_VAL2___diff_sz = 2,
};

typedef unsigned long int_typedef___diff_sz;

typedef enum an_enum___diff_sz enum_typedef___diff_sz;

typedef const void *const void_ptr_typedef___diff_sz;

typedef int_typedef___diff_sz (*func_proto_typedef___diff_sz)(char);

typedef int arr_typedef___diff_sz[2];

struct core_reloc_type_based___diff_sz {
	struct a_struct___diff_sz f1;
	union a_union___diff_sz f3;
	enum an_enum___diff_sz f4;
	named_struct_typedef___diff_sz f5;
	anon_struct_typedef___diff_sz f6;
	struct_ptr_typedef___diff_sz f7;
	int_typedef___diff_sz f8;
	enum_typedef___diff_sz f9;
	void_ptr_typedef___diff_sz f10;
	func_proto_typedef___diff_sz f12;
	arr_typedef___diff_sz f13;
};

/* incompatibilities between target and local types */
union a_struct___incompat { /* union instead of struct */
	int x;
};

struct a_union___incompat { /* struct instead of union */
	int y;
	int z;
};

/* typedef to union, not to struct */
typedef union a_struct___incompat named_struct_typedef___incompat;

/* typedef to void pointer, instead of struct */
typedef void *anon_struct_typedef___incompat;

/* extra pointer indirection */
typedef struct {
	int a, b, c;
} **struct_ptr_typedef___incompat;

/* typedef of a struct with int, instead of int */
typedef struct {
	int x;
} int_typedef___incompat;

/* typedef to func_proto, instead of enum */
typedef int (*enum_typedef___incompat)(void);

/* pointer to char instead of void */
typedef char *void_ptr_typedef___incompat;

/* void return type instead of int */
typedef void (*func_proto_typedef___incompat)(long);

/* multi-dimensional array instead of a single-dimensional */
typedef int arr_typedef___incompat[20][2];

struct core_reloc_type_based___incompat {
	union a_struct___incompat f1;
	struct a_union___incompat f3;
	/* the only valid one is enum, to check that something still succeeds */
	enum an_enum f4;
	named_struct_typedef___incompat f5;
	anon_struct_typedef___incompat f6;
	struct_ptr_typedef___incompat f7;
	int_typedef___incompat f8;
	enum_typedef___incompat f9;
	void_ptr_typedef___incompat f10;
	func_proto_typedef___incompat f12;
	arr_typedef___incompat f13;
};

struct core_reloc_type_based_output {
	bool struct_matches;
	bool complex_struct_matches;
	bool union_matches;
	bool enum_matches;
	bool typedef_named_struct_matches;
	bool typedef_anon_struct_matches;
	bool typedef_struct_ptr_matches;
	bool typedef_int_matches;
	bool typedef_enum_matches;
	bool typedef_void_ptr_matches;
	bool typedef_restrict_ptr_matches;
	bool typedef_func_proto_matches;
	bool typedef_arr_matches;
};

struct {
	char in[256];
	char out[256];
	bool skip;
} data = {};

#define __section(NAME) __attribute__((section(NAME), used))

void based(struct core_reloc_type_based x) {
}
void diff(struct core_reloc_type_based___diff x) {
}
void diff_sz(struct core_reloc_type_based___diff_sz x) {
}
void incompat(struct core_reloc_type_based___incompat x) {
}
