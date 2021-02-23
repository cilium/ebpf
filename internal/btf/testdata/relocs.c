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

__section("socket_filter/1") int type_ids() {
#define local_id_not(expr, val) \
	({ \
		if (bpf_core_type_id_local(expr) == val) { \
			return __LINE__; \
		} \
	})

#define kernel_id_not(expr, val) \
	({ \
		if (bpf_core_type_id_kernel(expr) == val) { \
			return __LINE__; \
		} \
	})

	// TODO: Anonymous types are not supported.
	// local_id_not(int, 0);
	// local_id_not(struct { int frob; }, 0);
	// local_id_not(enum {FRAP}, 0);

	local_id_not(struct s, 0);
	local_id_not(s_t, 0);
	local_id_not(const s_t, 0);
	local_id_not(volatile s_t, 0);
	local_id_not(enum e, 0);
	local_id_not(e_t, 0);
	local_id_not(const e_t, 0);
	local_id_not(volatile e_t, 0);

#undef local_id_not
	return 0;
}