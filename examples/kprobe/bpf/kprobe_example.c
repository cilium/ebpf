#include "../../../testdata/common.h"

char __license[] __section("license") = "GPL";

struct bpf_map_def __section("maps") kprobe_example_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 1,
};

__section("kprobe/__x64_sys_execve")
int kprobe_example_prog() {
    uint32_t key = 0;
    uint64_t initval = 1, *valp;

    valp = bpf_map_lookup_elem(&kprobe_example_map, &key);
    if (!valp) {
        bpf_map_update_elem(&kprobe_example_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);

    return 0;
}
