// +build ignore

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"


#define AF_INET	2
#define AF_INET6	10
#define TASK_COMM_LEN	16

const volatile __s32 target_pid = 0;

char __license[] SEC("license") = "Dual MIT/GPL";

/**
 * For CO-RE relocatable eBPF programs, __attribute__((preserve_access_index))
 * preserves the offset of the specified fields in the original kernel struct.
 * So here we don't need to include "vmlinux.h". Instead we only need to define
 * the kernel struct and their fields the eBPF program actually requires.
 *
 * Also note that BTF-enabled programs like fentry, fexit, fmod_ret, tp_btf,
 * lsm, etc. declared using the BPF_PROG macro can read kernel memory without
 * needing to call bpf_probe_read*().
 */

/**
 * struct in6_addr is the IPv6 address structure.
 * This is a simplified copy of the kernel's struct in6_addr.
 * This copy contains only the fields needed for this example to
 * fetch the IPv6 address.
 */
struct in6_addr {
	union {
		__be32 u6_addr32[4];
	} in6_u;
} __attribute__((preserve_access_index));

/**
 * struct sock_common is the minimal network layer representation of sockets.
 * This is a simplified copy of the kernel's struct sock_common.
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
    // skc_v6_rcv_saddr to access the IPv6 address
    struct in6_addr skc_v6_rcv_saddr;
	// skc_family is the network address family (2 for IPV4)
	short unsigned int skc_family;
} __attribute__((preserve_access_index));

/**
 * struct sock is the network layer representation of sockets.
 * This is a simplified copy of the kernel's struct sock.
 * This copy is needed only to access struct sock_common.
 */
struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

/**
 * struct socket - general BSD socket.
 * This is a simplified copy of the kernel's struct sock.
 * This copy is needed to access socket type and struct sock.
 */
struct socket {
    short int type;
    struct sock *sk;
} __attribute__((preserve_access_index));

/**
 * struct inet_sock - representation of INET sockets.
 * This is a simplified copy of the kernel's struct inet_sock.
 * This copy is needed only to access inet_sport.
 */
struct inet_sock {
    __be16 inet_sport;
} __attribute__((preserve_access_index));


struct event {
	__u32 pid;
	__u32 proto;
	int backlog;
	int ret;
	__u16 port;
	__u32 addr[4];
	u8 comm[TASK_COMM_LEN];
};

// Force emitting struct event into the ELF.
const struct event *unused_event __attribute__((unused));


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static void fill_event(struct event *event, struct socket *sock)
{
	__u16 family, type;
	struct sock *sk;
	struct inet_sock *inet;

	sk = BPF_CORE_READ(sock, sk);
	inet = (struct inet_sock *)sk;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	type = BPF_CORE_READ(sock, type);

	event->proto = ((__u32)family << 16) | type;
	event->port = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
	if (family == AF_INET)
		event->addr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	else if (family == AF_INET6)
		BPF_CORE_READ_INTO(event->addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

	/* sk = sock->sk;
	inet = (struct inet_sock *)sock->sk;
	family = sk->__sk_common.skc_family;
	type = sock->type;

	event->proto = ((__u32)family << 16) | type;
	// TODO There is a problem with inet->inet_sport pointer access. error: "access beyond struct sock at off 808 size 2"
	event->port = bpf_ntohs(inet->inet_sport);  
	if (family == AF_INET)
		event->addr[0] = sk->__sk_common.skc_rcv_saddr;
	else if (family == AF_INET6)
		bpf_probe_read_kernel(event->addr, sizeof(event->addr),
                           sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32); */
	bpf_get_current_comm(event->comm, sizeof(event->comm));
}

SEC("fexit/inet_listen")
int BPF_PROG(inet_listen_fexit, struct socket *sock, int backlog, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct event event = {} ;

	if (target_pid && target_pid != pid)
		return 0;

	fill_event(&event, sock);

	event.pid = pid_tgid;
	event.backlog = backlog;
	event.ret = ret;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}
