#include "../../testdata/common.h"
#include "bpf_core_read.h"

enum e {
	// clang-12 doesn't allow enum relocations with zero value.
	// See https://reviews.llvm.org/D97659
	ONE = 1,
	TWO,
};

typedef enum e e_t;

struct s {
	int _1;
	char _2;
	unsigned int _3;
};

typedef struct s s_t;

union u {
	int *_1;
	char *_2;
	unsigned int *_3;
};

typedef union u u_t;

#define local_id_zero(expr) \
	({ \
		if (bpf_core_type_id_local(expr) != 0) { \
			return __LINE__; \
		} \
	})

#define local_id_not_zero(expr) \
	({ \
		if (bpf_core_type_id_local(expr) == 0) { \
			return __LINE__; \
		} \
	})

#define target_and_local_id_match(expr) \
	({ \
		if (bpf_core_type_id_kernel(expr) != bpf_core_type_id_local(expr)) { \
			return __LINE__; \
		} \
	})

__section("socket_filter/type_ids") int type_ids() {
	local_id_not_zero(int);
	local_id_not_zero(struct { int frob; });
	local_id_not_zero(enum {FRAP});
	local_id_not_zero(union { char bar; });

	local_id_not_zero(struct s);
	local_id_not_zero(s_t);
	local_id_not_zero(const s_t);
	local_id_not_zero(volatile s_t);
	local_id_not_zero(enum e);
	local_id_not_zero(e_t);
	local_id_not_zero(const e_t);
	local_id_not_zero(volatile e_t);
	local_id_not_zero(union u);
	local_id_not_zero(u_t);
	local_id_not_zero(const u_t);
	local_id_not_zero(volatile u_t);

	// Qualifiers on types crash clang.
	target_and_local_id_match(struct s);
	target_and_local_id_match(s_t);
	// target_and_local_id_match(const s_t);
	// target_and_local_id_match(volatile s_t);
	target_and_local_id_match(enum e);
	target_and_local_id_match(e_t);
	// target_and_local_id_match(const e_t);
	// target_and_local_id_match(volatile e_t);
	target_and_local_id_match(union u);
	target_and_local_id_match(u_t);
	// target_and_local_id_match(const u_t);
	// target_and_local_id_match(volatile u_t);

	return 0;
}

#define type_exists(expr) \
	({ \
		if (!bpf_core_type_exists(expr)) { \
			return __LINE__; \
		} \
	})

#define type_size_matches(expr) \
	({ \
		if (bpf_core_type_size(expr) != sizeof(expr)) { \
			return __LINE__; \
		} \
	})

__section("socket_filter/types") int types() {
	type_exists(struct s);
	type_exists(s_t);
	type_exists(const s_t);
	type_exists(volatile s_t);
	type_exists(enum e);
	type_exists(e_t);
	type_exists(const e_t);
	type_exists(volatile e_t);
	type_exists(union u);
	type_exists(u_t);
	type_exists(const u_t);
	type_exists(volatile u_t);
	// TODO: Check non-existence.

	type_size_matches(struct s);
	type_size_matches(s_t);
	type_size_matches(const s_t);
	type_size_matches(volatile s_t);
	type_size_matches(enum e);
	type_size_matches(e_t);
	type_size_matches(const e_t);
	type_size_matches(volatile e_t);
	type_size_matches(union u);
	type_size_matches(u_t);
	type_size_matches(const u_t);
	type_size_matches(volatile u_t);

	return 0;
}

#define enum_value_exists(t, v) \
	({ \
		if (!bpf_core_enum_value_exists(t, v)) { \
			return __LINE__; \
		} \
	})

#define enum_value_matches(t, v) \
	({ \
		if (v != bpf_core_enum_value(t, v)) { \
			return __LINE__; \
		} \
	})

__section("socket_filter/enums") int enums() {
	enum_value_exists(enum e, ONE);
	enum_value_exists(volatile enum e, ONE);
	enum_value_exists(const enum e, ONE);
	enum_value_exists(e_t, TWO);
	// TODO: Check non-existence.

	enum_value_matches(enum e, TWO);
	enum_value_matches(e_t, ONE);
	enum_value_matches(volatile e_t, ONE);
	enum_value_matches(const e_t, ONE);

	return 0;
}

#define field_exists(f) \
	({ \
		if (!bpf_core_field_exists(f)) { \
			return __LINE__; \
		} \
	})

#define field_size_matches(f) \
	({ \
		if (sizeof(f) != bpf_core_field_size(f)) { \
			return __LINE__; \
		} \
	})

#define field_offset_matches(t, f) \
	({ \
		if (__builtin_offsetof(t, f) != __builtin_preserve_field_info(((typeof(t) *)0)->f, BPF_FIELD_BYTE_OFFSET)) { \
			return __LINE__; \
		} \
	})

#define field_is_signed(f) \
	({ \
		if (!__builtin_preserve_field_info(f, BPF_FIELD_SIGNED)) { \
			return __LINE__; \
		} \
	})

#define field_is_unsigned(f) \
	({ \
		if (__builtin_preserve_field_info(f, BPF_FIELD_SIGNED)) { \
			return __LINE__; \
		} \
	})

__section("socket_filter/fields") int fields() {
	field_exists((struct s){}._1);
	field_exists((s_t){}._2);
	field_exists((union u){}._1);
	field_exists((u_t){}._2);

	field_is_signed((struct s){}._1);
	field_is_unsigned((struct s){}._3);
	// unions crash clang-14.
	// field_is_signed((union u){}._1);
	// field_is_unsigned((union u){}._3);

	field_size_matches((struct s){}._1);
	field_size_matches((s_t){}._2);
	field_size_matches((union u){}._1);
	field_size_matches((u_t){}._2);

	field_offset_matches(struct s, _1);
	field_offset_matches(s_t, _2);
	field_offset_matches(union u, _1);
	field_offset_matches(u_t, _2);

	struct t {
		union {
			s_t s[10];
		};
		struct {
			union u u;
		};
	} bar, *barp = &bar;

	field_exists(bar.s[2]._1);
	field_exists(bar.s[1]._2);
	field_exists(bar.u._1);
	field_exists(bar.u._2);
	field_exists(barp[1].u._2);

	field_is_signed(bar.s[2]._1);
	field_is_unsigned(bar.s[2]._3);
	// unions crash clang-14.
	// field_is_signed(bar.u._1);
	// field_is_signed(bar.u._3);

	field_size_matches(bar.s[2]._1);
	field_size_matches(bar.s[1]._2);
	field_size_matches(bar.u._1);
	field_size_matches(bar.u._2);
	field_size_matches(barp[1].u._2);

	field_offset_matches(struct t, s[2]._1);
	field_offset_matches(struct t, s[1]._2);
	field_offset_matches(struct t, u._1);
	field_offset_matches(struct t, u._2);

	return 0;
}

struct ambiguous {
	int _1;
	char _2;
};

struct ambiguous___flavour {
	char _1;
	int _2;
};

__section("socket_filter/err_ambiguous") int err_ambiguous() {
	return bpf_core_type_id_kernel(struct ambiguous);
}

__section("socket_filter/err_ambiguous_flavour") int err_ambiguous_flavour() {
	return bpf_core_type_id_kernel(struct ambiguous___flavour);
}
