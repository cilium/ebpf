#include "../../../testdata/common.h"
#include "bpf_core_read.h"

enum e {
	ONE,
	TWO,
	THREE,
};

typedef enum e e_t;

struct s {
	int _1;
	char _2;
};

typedef struct s s_t;

#define local_id_not(expr, val) \
	({ \
		if (bpf_core_type_id_local(expr) == val) { \
			return __LINE__; \
		} \
	})

#define target_id_not(expr, val) \
	({ \
		if (bpf_core_type_id_kernel(expr) == val) { \
			return __LINE__; \
		} \
	})

__section("socket_filter/type_ids") int type_ids() {
	local_id_not(int, 0);
	local_id_not(
		struct { int frob; }, 0);
	local_id_not(enum {FRAP}, 0);

	local_id_not(struct s, 0);
	local_id_not(s_t, 0);
	local_id_not(const s_t, 0);
	local_id_not(volatile s_t, 0);
	local_id_not(enum e, 0);
	local_id_not(e_t, 0);
	local_id_not(const e_t, 0);
	local_id_not(volatile e_t, 0);

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
	target_id_not(struct ambiguous, 0);
	return 0;
}

__section("socket_filter/err_ambiguous_flavour") int err_ambiguous_flavour() {
	target_id_not(struct ambiguous___flavour, 0);
	return 0;
}
