#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include <uapi/linux/pkt_cls.h>

SEC("classifier/egress")
int egress_cls_func(struct __sk_buff *skb)
{
    bpf_printk("new packet captured on egress (TC)\n");
    return TC_ACT_OK;
};

SEC("classifier/ingress")
int ingress_cls_func(struct __sk_buff *skb)
{
    bpf_printk("new packet captured on ingress (TC)\n");
    return TC_ACT_OK;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
