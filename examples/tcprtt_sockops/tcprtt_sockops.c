// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_sockops.h"
#include "bpf_tracing.h"
#include "tcprtt_sockops.h"

char __license[] SEC("license") = "Dual MIT/GPL";

static inline void init_sk_key(struct bpf_sock_ops *skops, struct sk_key *sk_key) {
	sk_key->local_ip4   = bpf_ntohl(skops->local_ip4);
	sk_key->remote_ip4  = bpf_ntohl(skops->remote_ip4);
	sk_key->local_port  = skops->local_port;
	sk_key->remote_port = bpf_ntohl(skops->remote_port);
}

static inline void bpf_sock_ops_establish_cb(struct bpf_sock_ops *skops, u8 sock_type) {
	int err;
	struct sk_info sk_info = {};
	if (skops == NULL || skops->family != AF_INET)
		return;

	init_sk_key(skops, &sk_info.sk_key);
	sk_info.sk_type = sock_type;

	err = bpf_map_update_elem(&map_estab_sk, &sk_info.sk_key, &sk_info, BPF_NOEXIST);
	if (err != 0)
		return;

	bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTT_CB_FLAG | BPF_SOCK_OPS_STATE_CB_FLAG);
}

static inline void bpf_sock_ops_rtt_cb(struct bpf_sock_ops *skops) {
	struct sk_key sk_key = {};
	struct sk_info *sk_info;
	struct rtt_event *rtt_event;

	init_sk_key(skops, &sk_key);

	sk_info = bpf_map_lookup_elem(&map_estab_sk, &sk_key);
	if (!sk_info)
		return;

	rtt_event = bpf_ringbuf_reserve(&rtt_events, sizeof(struct rtt_event), 0);
	if (!rtt_event) {
		return;
	}

	switch (sk_info->sk_type) {
	case SOCK_TYPE_ACTIVE:
		rtt_event->saddr   = sk_info->sk_key.local_ip4;
		rtt_event->daddr   = sk_info->sk_key.remote_ip4;
		rtt_event->sport   = sk_info->sk_key.local_port;
		rtt_event->dport   = sk_info->sk_key.remote_port;
		rtt_event->sk_type = SOCK_TYPE_ACTIVE;
		break;
	case SOCK_TYPE_PASSIVE:
		rtt_event->saddr   = sk_info->sk_key.remote_ip4;
		rtt_event->daddr   = sk_info->sk_key.local_ip4;
		rtt_event->sport   = sk_info->sk_key.remote_port;
		rtt_event->dport   = sk_info->sk_key.local_port;
		rtt_event->sk_type = SOCK_TYPE_PASSIVE;
		break;
	}

	rtt_event->srtt = skops->srtt_us >> 3;
	rtt_event->srtt /= 1000;

	bpf_printk("TCP RTT sip 0x%x", rtt_event->saddr);
	bpf_printk("\tdip 0x%x", rtt_event->daddr);
	bpf_printk("\tsport %d", rtt_event->sport);
	bpf_printk("\tdport %d", rtt_event->dport);
	bpf_printk("\tRTT %d", rtt_event->srtt);

	bpf_ringbuf_submit(rtt_event, 0);
}

static inline void bpf_sock_ops_state_cb(struct bpf_sock_ops *skops) {
	struct sk_key sk_key = {};

	if (skops->args[0] == TCP_ESTABLISHED) {
		init_sk_key(skops, &sk_key);
		bpf_map_delete_elem(&map_estab_sk, &sk_key);
	}
}

SEC("sockops")
int bpf_sockops_cb(struct bpf_sock_ops *skops) {
	u32 op;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_sock_ops_establish_cb(skops, SOCK_TYPE_ACTIVE);
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_sock_ops_establish_cb(skops, SOCK_TYPE_PASSIVE);
		break;
	case BPF_SOCK_OPS_RTT_CB:
		bpf_sock_ops_rtt_cb(skops);
		break;
	case BPF_SOCK_OPS_STATE_CB:
		bpf_sock_ops_state_cb(skops);
		break;
	}

	return 0;
}
