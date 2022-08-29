/*
 * Note that this header file contains a subset of kernel 
 * definitions needed for the tcprtt_sockops example.
 */
#ifndef BPF_SOCKOPS_H
#define BPF_SOCKOPS_H

/*
 * Copy of TCP states.
 * See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L6347.
 */
enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_MAX_STATES = 13,
};

/*
 * Copy of sock_ops operations.
 * See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L6233.
 */
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

/*
 * Copy of definitions for bpf_sock_ops_cb_flags.
 * See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L6178.
 */
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

/*
 * Copy of bpf.h's bpf_sock_ops with minimal subset 
 * of fields used by the tcprtt_sockops example.
 * See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L6101.
 */
struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];
		__u32 reply;
		__u32 replylong[4];
	};
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_port;
	__u32 local_port;
	__u32 srtt_us;
    __u32 bpf_sock_ops_cb_flags;
} __attribute__((preserve_access_index));

#endif