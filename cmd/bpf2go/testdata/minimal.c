#include "../../../testdata/common.h"

char __license[] __section("license") = "MIT";

struct bpf_map_def map1 __section("maps") = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 1,
};

__section("socket") int filter() {
	return 0;
}
