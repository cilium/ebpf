#ifndef TCPRTT_SOCKOPS_H
#define TCPRTT_SOCKOPS_H

#define AF_INET 2

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

enum {
	BPF_SOCK_OPS_RTO_CB_FLAG                   = 1,
	BPF_SOCK_OPS_RETRANS_CB_FLAG               = 2,
	BPF_SOCK_OPS_STATE_CB_FLAG                 = 4,
	BPF_SOCK_OPS_RTT_CB_FLAG                   = 8,
	BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG     = 16,
	BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG = 32,
	BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG         = 64,
	BPF_SOCK_OPS_ALL_CB_FLAGS                  = 127,
};

struct bpf_sock_ops {
	__u32 op;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_port;
	__u32 local_port;
	__u32 srtt_us;
    __u32 bpf_sock_ops_cb_flags;
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
    u32 srtt;
};
struct event *unused_event __attribute__((unused));

#endif