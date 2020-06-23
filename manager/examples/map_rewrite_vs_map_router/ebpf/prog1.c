#include "include/bpf.h"
#include "include/bpf_map.h"
#include "include/bpf_helpers.h"

// shared_cache - This map will be shared with other Manager
struct bpf_map_def SEC("maps/shared_cache1") shared_cache1 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

// shared_cache2 - This map will be shared with other Manager
struct bpf_map_def SEC("maps/shared_cache2") shared_cache2 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

SEC("kretprobe/vfs_mkdir")
int kretprobe_vfs_mkdir(void *ctx)
{
    // retrieve the value saved in the cache at key 1
    u32 key = 1;
    u32 *value = bpf_map_lookup_elem(&shared_cache1, &key);
    if (!value) {
        bpf_printk("(prog1) shared_cache1 is empty\n");
    } else {
        bpf_printk("(prog1) shared_cache1 contains %u\n", *value);
    }

    value = bpf_map_lookup_elem(&shared_cache2, &key);
    if (!value) {
        bpf_printk("(prog1) shared_cache2 is empty\n");
    } else {
        bpf_printk("(prog1) shared_cache2 contains %u\n", *value);
    }
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
