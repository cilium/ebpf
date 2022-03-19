// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		unsigned int skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
};

struct sock {
	struct sock_common __sk_common;
};

struct tcp_sock {
	u32 srtt_us;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct event {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u32 srtt;
};

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk) {
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}
	
	struct tcp_sock *ts = (struct tcp_sock *)(sk);
	if (!ts) {
		return 0;
	}

	struct event *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!tcp_info) {
		return 0;
	}

	tcp_info->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	tcp_info->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	tcp_info->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	tcp_info->sport = bpf_htons(BPF_CORE_READ(sk, __sk_common.skc_num));
	
	tcp_info->srtt = BPF_CORE_READ(ts, srtt_us) >> 3;
	tcp_info->srtt /= 1000;

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}
