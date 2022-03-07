/*
	This file exists to emit ELFs with specific BTF types to use as target BTF
	in tests. It can be made redundant when btf.Spec can be handcrafted and
	passed as a CO-RE target in the future.
*/

#define core_access __builtin_preserve_access_index

struct s {
	char a;
	char b;
};

int dummy() {
	return core_access((struct s){}.a);
}
