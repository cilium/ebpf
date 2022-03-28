/*
	This file exists to emit ELFs with specific BTF types to use as target BTF
	in tests. It can be made redundant when btf.Spec can be handcrafted and
	passed as a CO-RE target in the future.
*/

struct s {
	char a;
	char b;
} __attribute__((preserve_access_index));

struct s *unused_s __attribute__((unused));
