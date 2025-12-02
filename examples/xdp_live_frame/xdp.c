//go:build ignore

// XDP program for demonstrating BPF_F_TEST_XDP_LIVE_FRAMES.
// When run in live frame mode, the provided packet data is sent directly
// to the network interface based on the XDP program's return value.

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// xdp_prog_tx returns XDP_TX to transmit the packet back out the same interface.
// This is used with BPF_F_TEST_XDP_LIVE_FRAMES for packet generation.
SEC("xdp")
int xdp_prog_tx(struct xdp_md *ctx) {
	return XDP_TX;
}

// xdp_prog_pass is attached to the interface to enable XDP_TX.
// XDP_TX requires an XDP program to be attached to the target interface.
SEC("xdp")
int xdp_prog_pass(struct xdp_md *ctx) {
	return XDP_PASS;
}
