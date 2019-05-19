#include "common.h"

char __license[] __section("license") = "GPL";

struct map events __section("maps") = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

__section("xdp/single") int output_single(void *ctx) {
	unsigned char buf[] = {
		1, 2, 3, 4, 5
	};

	return perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &buf[0], sizeof(buf));
}

__section("xdp/large") int output_large(void *ctx) {
	unsigned char buf[180];
	__builtin_memset(buf, 0, sizeof(buf));

	return perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &buf[0], sizeof(buf));
}
