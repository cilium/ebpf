#include "include/bpf.h"
#include "include/bpf_map.h"
#include "include/bpf_helpers.h"

#include <uapi/linux/pkt_cls.h>

#define TAIL_CALL_KEY 1
#define EXTERNAL_TAIL_CALL_KEY 2

struct bpf_map_def SEC("maps/tc_prog_array") tc_prog_array = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = 4,
    .value_size = 4,
    .max_entries = 3,
};

SEC("classifier/one")
int classifier_one(struct __sk_buff *skb)
{
    bpf_printk("(classifier/one) new packet captured (TC)\n");

    // Tail call
    int key = TAIL_CALL_KEY;
    bpf_tail_call(skb, &tc_prog_array, key);

    // Tail call failed
    bpf_printk("(classifier/one) couldn't tail call (TC)\n");
    return TC_ACT_OK;
};

SEC("classifier/two")
int classifier_two(struct __sk_buff *skb)
{
    bpf_printk("(classifier/two) tail call triggered (TC)\n");

    // Tail call
    int key = EXTERNAL_TAIL_CALL_KEY;
    bpf_tail_call(skb, &tc_prog_array, key);

    // Tail call failed
    bpf_printk("(classifier/two) external tail call failed (TC)\n");
    return TC_ACT_OK;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
