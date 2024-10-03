#include "../../testdata/common.h"

#define tagA __attribute__((btf_decl_tag("a")))
#define tagB __attribute__((btf_decl_tag("b")))
#define tagC __attribute__((btf_decl_tag("c")))
#define tagD __attribute__((btf_decl_tag("d")))
#define tagE __attribute__((btf_decl_tag("e")))

struct s {
	char tagA foo;
	char tagB bar;
} tagC;

union u {
	char tagA foo;
	char tagB bar;
} tagC;

typedef tagB char td;

struct s tagD s1;
union u tagE u1;
td tagA t1;

int tagA tagB fwdDecl(char tagC x, char tagD y);

int tagE normalDecl1(char tagB x, char tagC y) {
	return fwdDecl(x, y);
}

int tagE normalDecl2(char tagB x, char tagC y) {
	return fwdDecl(x, y);
}

__section("syscall") int prog(char *ctx) {
	return normalDecl1(ctx[0], ctx[1]) + normalDecl2(ctx[2], ctx[3]);
}
