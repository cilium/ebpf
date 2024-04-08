//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

#include "bpf_sockops.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct toa_data_s {
    u8  kind;
    u8  len;
    u16 port;
    u32 addr;
};

SEC("sockops")
int bpf_sockops_cb(struct bpf_sock_ops *skops) {

    u32 op = skops->op;
    s32 rv = -1;
    s32 ret;

    switch (op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:

        ret = bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);

        break;

    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:

        rv = sizeof(struct toa_data_s);

        ret = bpf_reserve_hdr_opt(skops, rv, 0);

        break;

    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
        {

            struct toa_data_s toa_data = {
                .kind = 254,
                .len  = 0x08,
                .port = 8888,
                .addr = 50529027, // 4.4.4.4
            };

            ret = bpf_store_hdr_opt(skops, &toa_data, sizeof(toa_data), 0);

            break;
        }
    }

    skops->reply = rv;

    return 1;
}
