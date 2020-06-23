#include "include/bpf.h"
#include "include/bpf_helpers.h"

SEC("xdp/ingress")
int egress_cls_func(struct __sk_buff *skb)
{
    bpf_printk("new packet captured (XDP)\n");
    return XDP_PASS;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
