#include "common.h"

char __license[] __section("license") = "GPL";

struct map events __section("maps") = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

__section("xdp/single") int output_single(void *ctx) {
	unsigned char buf[] = {
		1, 2, 3, 4, 5
	};

	return perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &buf[0], 5);
}

__section("xdp/lost") int create_lost_sample(void *ctx) {
	unsigned char buf[128];
	__builtin_memset(buf, 0, sizeof(buf));

	uint32_t cpu = get_smp_processor_id();

	// Submitting an 128 byte event ends up using
	// 144 bytes in the ring buffer.
	// Fill the ring buffer up to 4032 bytes, and generate a lost
	// event by writing an additional event.
	#pragma unroll
	for (int i = 0; i < (4096 / 144) + 1; i++) {
		int ret = perf_event_output(ctx, &events, cpu, &buf[0], sizeof(buf));
		if (ret) {
			return ret;
		}
	}

	// Lost sample events are generated opportunistically, when the kernel
	// is writing an event and realises that there were events lost previously.
	// Generate a small event to trigger this.
	return perf_event_output(ctx, &events, cpu, &buf[0], 1);
}
