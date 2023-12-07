#include "../../../testdata/common.h"

char __license[] __section("license") = "MIT";

enum e { HOOPY, FROOD };

typedef long long int longint;

typedef struct {
	longint bar;
	_Bool baz;
	enum e boo;
} barfoo;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, enum e);
	__type(value, barfoo);
	__uint(max_entries, 1);
} map1 __section(".maps");

volatile const enum e my_constant = FROOD;

volatile const barfoo struct_const;

__section("socket") int filter() {
	return my_constant + struct_const.bar;
}
