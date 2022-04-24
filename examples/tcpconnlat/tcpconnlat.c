// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

#define AF_INET 2
#define TCP_SYN_SENT 2

char __license[] SEC("license") = "Dual MIT/GPL";

/**
 * This example copies parts of struct sock_common and struct sock from
 * the Linux kernel, but doesn't cause any CO-RE information to be emitted
 * into the ELF object. This requires the struct layout (up until the fields
 * that are being accessed) to match the kernel's, and the example will break
 * or misbehave when this is no longer the case.
 *
 * Also note that BTF-enabled programs like fentry, fexit, fmod_ret, tp_btf,
 * lsm, etc. declared using the BPF_PROG macro can read kernel memory without
 * needing to call bpf_probe_read*().
 */

/**
 * struct sock_common reflects the start of the kernel's struct sock_common.
 * It only contains the fields up until skc_state that are accessed in the
 * program, with padding to match the kernel's declaration.
 */
struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		// Padding out union skc_hash.
		__u32 _;
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	volatile unsigned char skc_state;
};

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
struct sock {
	struct sock_common __sk_common;
};

/**
 * The connection information cached in BPF map, used for calculating
 * connection latency.
 */
struct conn_info {
	u64 ts;
	u32 pid;
	u32 pad;
};

struct bpf_map_def SEC("maps") conn_store = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(void *),
	.value_size  = sizeof(struct conn_info),
	.max_entries = 1 << 16,
};

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u32 latency_us;
};
struct event *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24 /* 16MB */);
} events SEC(".maps");

SEC("fentry/tcp_v4_connect")
int BPF_PROG(tcp_v4_connect, struct sock *sk) {
	u64 ts  = bpf_ktime_get_ns();
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct conn_info info = {.ts = ts, .pid = pid};

	// Save connection info for latency calculation
	if (bpf_map_update_elem(&conn_store, &sk, &info, 0)) {
		return 0;
	}

	return 0;
}

// See tcp_v4_do_rcv(). TCP_ESTBALISHED and TCP_LISTEN
// are fast path and processed elsewhere, and leftovers are processed by
// tcp_rcv_state_process(). We can trace this for handshake completion.
SEC("fentry/tcp_rcv_state_process")
int BPF_PROG(tcp_rcv_state_process, struct sock *sk) {
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}

	// Will be in TCP_SYN_SENT for handshake
	if (sk->__sk_common.skc_state != TCP_SYN_SENT) {
		return 0;
	}

	// Retrieve connection info and calculate elapsed time
	struct conn_info *info = bpf_map_lookup_elem(&conn_store, &sk);
	if (!info) {
		return 0; // missed entry or filtered
	}

	u32 latency_us = (bpf_ktime_get_ns() - info->ts) / 1000ul;
	bpf_map_delete_elem(&conn_store, &sk);

	// Submit an event
	struct event *ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!ev) {
		return 0;
	}

	ev->saddr      = sk->__sk_common.skc_rcv_saddr;
	ev->daddr      = sk->__sk_common.skc_daddr;
	ev->sport      = sk->__sk_common.skc_num;
	ev->dport      = bpf_ntohs(sk->__sk_common.skc_dport);
	ev->latency_us = latency_us;

	bpf_ringbuf_submit(ev, 0);

	return 0;
}
