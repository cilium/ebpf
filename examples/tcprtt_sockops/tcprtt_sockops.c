// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

#define AF_INET 2

char __license[] SEC("license") = "Dual MIT/GPL";

enum {
	BPF_SOCK_OPS_VOID                   = 0,
	BPF_SOCK_OPS_TIMEOUT_INIT           = 1,
	BPF_SOCK_OPS_RWND_INIT              = 2,
	BPF_SOCK_OPS_TCP_CONNECT_CB         = 3,
	BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB  = 4,
	BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB = 5,
	BPF_SOCK_OPS_NEEDS_ECN              = 6,
	BPF_SOCK_OPS_BASE_RTT               = 7,
	BPF_SOCK_OPS_RTO_CB                 = 8,
	BPF_SOCK_OPS_RETRANS_CB             = 9,
	BPF_SOCK_OPS_STATE_CB               = 10,
	BPF_SOCK_OPS_TCP_LISTEN_CB          = 11,
	BPF_SOCK_OPS_RTT_CB                 = 12,
	BPF_SOCK_OPS_PARSE_HDR_OPT_CB       = 13,
	BPF_SOCK_OPS_HDR_OPT_LEN_CB         = 14,
	BPF_SOCK_OPS_WRITE_HDR_OPT_CB       = 15,
};

struct bpf_sock_ops {
	__u32 op;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_port;
	__u32 local_port;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
};
struct event *unused_event __attribute__((unused));

SEC("sockops")
int bpf_sockops_cb(struct bpf_sock_ops *skops) {
	u32 family;
	u32 op;

	family = skops->family;
	op     = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		if (family != AF_INET)
			break;

		struct event *tcp_info;
		tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
		if (!tcp_info) {
			return 0;
		}

		tcp_info->saddr = bpf_ntohl(skops->local_ip4);
		tcp_info->daddr = bpf_ntohl(skops->remote_ip4);
		tcp_info->sport = skops->local_port;
		tcp_info->dport = bpf_ntohl(skops->remote_port);

		bpf_printk("TCP Connect sip 0x%x", tcp_info->saddr);
		bpf_printk("dip 0x%x", tcp_info->daddr);
		bpf_printk("sport %d", tcp_info->sport);
		bpf_printk("dport %d", tcp_info->dport);

		bpf_ringbuf_submit(tcp_info, 0);

		break;
	}

	return 0;
}
