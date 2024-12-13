#include "../../../testdata/common.h"

char __license[] __section("license") = "MIT";

enum e { HOOPY, FROOD };

typedef long long int longint;

typedef struct {
	longint bar;
	_Bool baz;
	enum e boo;
} barfoo;

typedef struct {
	uint64_t a;
} baz;

struct bar {
	uint64_t a;
	uint32_t b;
};

union ubar {
	uint32_t a;
	uint64_t b;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, enum e);
	__type(value, barfoo);
	__uint(max_entries, 1);
} map1 __section(".maps");

volatile const int an_int;
volatile const enum e my_constant = FROOD;
volatile const int int_array[2];
volatile const barfoo struct_const;
volatile const baz struct_array[2];

volatile struct bar struct_var;
volatile union ubar union_var;

__section("socket") int filter() {
	return my_constant + struct_const.bar;
}
