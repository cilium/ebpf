#include "bpf_core_read.h"

enum cgroup_subsys_id {
	cpuset_cgrp_id,
	cpuset_cgrp_id_lublub,
	CGROUP_SUBSYS_COUNT,
};

#define __section(NAME) __attribute__((section(NAME), used))

__section("socket/core_ld64imm") int core_ld64imm() {
	if (bpf_core_enum_value_exists(enum cgroup_subsys_id, cpuset_cgrp_id_lublub)) {
		__attribute__((unused)) const volatile int val = bpf_core_enum_value(enum cgroup_subsys_id, cpuset_cgrp_id_lublub);
	}
	return 0;
}
