#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") skb_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

SEC("cgroup_skb/egress")
int count_egress_packets(struct __sk_buff *skb) {
    u32 key = 0;
    u64 init_val = 1, *count = bpf_map_lookup_elem(&skb_map, &key);
    if (!count) {
        bpf_map_update_elem(&skb_map, &key, &init_val, BPF_ANY);
        return 1;
    }
    __sync_fetch_and_add(count, 1);

  return 1;
}
