#include "include/bpf.h"
#include "include/bpf_map.h"
#include "include/bpf_helpers.h"

#include <uapi/linux/pkt_cls.h>

SEC("classifier/three")
int classifier_three(struct __sk_buff *skb)
{
    bpf_printk("(classifier/three) tail call triggered (TC)\n");
    return TC_ACT_OK;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
