/*
	This file exists to emit ELFs with specific BTF types to use as target BTF
	in tests. It can be made redundant when btf.Spec can be handcrafted and
	passed as a CO-RE target in the future.
*/

struct s {
	char a;
	char b;
};

struct s *unused_s __attribute__((unused));

typedef unsigned int my_u32;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

struct bits {
	/*int x;*/
	u8 b : 2, a : 4; /* a was before b */
	my_u32 d : 2;    /* was 'unsigned int' */
	u16 c : 1;       /* was before d */
	enum { ZERO = 0, ONE = 1 } e : 1;
	u16 f;      /* was: u64 f:16 */
	u32 g : 30; /* was: u64 g:30 */
};

struct bits *unused_bits __attribute__((unused));
