//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

#define AF_INET 2
#define TASK_COMM_LEN 16

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
 * It only contains the fields up until skc_family that are accessed in the
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
};

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
struct sock {
	struct sock_common __sk_common;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event {
	u8 comm[16];
	__u16 sport;
	__be16 dport;
	__be32 saddr;
	__be32 daddr;
};
struct event *unused __attribute__((unused));

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}

	struct event *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!tcp_info) {
		return 0;
	}

	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->daddr = sk->__sk_common.skc_daddr;
	tcp_info->dport = sk->__sk_common.skc_dport;
	tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);

	bpf_get_current_comm(&tcp_info->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}
