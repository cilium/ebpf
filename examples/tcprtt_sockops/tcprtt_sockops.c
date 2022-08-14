// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "tcprtt_sockops.h"

char __license[] SEC("license") = "Dual MIT/GPL";

static inline void bpf_sock_ops_establish_cb(struct bpf_sock_ops *skops) {
	if (skops == NULL || skops->family != AF_INET)
		return;
	bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTT_CB_FLAG);
}

static inline void bpf_sock_ops_rtt_cb(struct bpf_sock_ops *skops) {
	struct event *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!tcp_info) {
		return;
	}

	tcp_info->saddr = bpf_ntohl(skops->local_ip4);
	tcp_info->daddr = bpf_ntohl(skops->remote_ip4);
	tcp_info->sport = skops->local_port;
	tcp_info->dport = bpf_ntohl(skops->remote_port);
	tcp_info->srtt  = skops->srtt_us >> 3;
	tcp_info->srtt /= 1000;

	bpf_printk("TCP RTT sip 0x%x", tcp_info->saddr);
	bpf_printk("dip 0x%x", tcp_info->daddr);
	bpf_printk("sport %d", tcp_info->sport);
	bpf_printk("dport %d", tcp_info->dport);
	bpf_printk("RTT %d", tcp_info->srtt);

	bpf_ringbuf_submit(tcp_info, 0);
}

SEC("sockops")
int bpf_sockops_cb(struct bpf_sock_ops *skops) {
	u32 op;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_sock_ops_establish_cb(skops);
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_sock_ops_establish_cb(skops);
		break;
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		bpf_sock_ops_establish_cb(skops);
		break;
	case BPF_SOCK_OPS_RTT_CB:
		bpf_sock_ops_rtt_cb(skops);
		break;
	}

	return 0;
}
