// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/**
 * Note: for CO-RE relocatable eBPF programs, __attribute__((preserve_access_index))
 * preserves the offset of the specified fields in the original kernel struct.
 * So here we don't need to include "vmlinux.h". Instead we only need to define
 * the kernel struct and their fields the eBPF program actually requires.
 */

/**
 * struct sock_common is the minimal network layer representation of sockets.
 * This is a simplified copy of the same kernel's struct:
 * (https://elixir.bootlin.com/linux/latest/source/include/net/sock.h#L163).
 * This copy contains only the fields needed for this example to 
 * fetch the source and destination port numbers and IP addresses.
 */
struct sock_common {
	union {
		struct {
			// skc_daddr is destination IP address
			__be32 skc_daddr;
			// skc_rcv_saddr is the source IP address
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			// skc_dport is the destination TCP/UDP port
			__be16 skc_dport;
			// skc_num is the source TCP/UDP port
			__u16 skc_num;
		};
	};
	// skc_family is the network address family (2 for IPV4)
	short unsigned int skc_family;
} __attribute__((preserve_access_index)); 


/**
 * struct sock is the network layer representation of sockets.
 * This is a simplified copy of the same kernel's struct:
 * (https://elixir.bootlin.com/linux/latest/source/include/net/sock.h#L355).
 * This copy is needed only to access struct sock_common.
 */
struct sock {
	struct sock_common __sk_common;
}  __attribute__((preserve_access_index));


/**
 * struct tcp_sock is the Linux representation of a TCP socket. 
 * This is a simplified copy of the same kernel's struct:
 * https://elixir.bootlin.com/linux/latest/source/include/linux/tcp.h#L145 
 * For this example we only need srtt_us to read the smoothed RTT.
 */
struct tcp_sock {
	u32 srtt_us;
} __attribute__((preserve_access_index));

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
	
	// The input struct sock is actually a tcp_sock, so we can type-cast
	struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
	if (!ts) {
		return 0;
	}

	struct event *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!tcp_info) {
		return 0;
	}

	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->daddr = sk->__sk_common.skc_daddr;
	tcp_info->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	tcp_info->sport = sk->__sk_common.skc_num;
	
	tcp_info->srtt = ts->srtt_us >> 3;
	tcp_info->srtt /= 1000;

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}
