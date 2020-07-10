#include "include/bpf.h"
#include "include/bpf_map.h"
#include "include/bpf_helpers.h"

struct bpf_map_def SEC("maps/map1") map1 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps/map2") map2 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

__attribute__((always_inline)) static int mkdir(int t) {
    // Check if map has some data
    u32 key = 1;
    u32 *data = bpf_map_lookup_elem(&map1, &key);
    if (data == NULL) {
        bpf_printk("(mkdir %d) map1 is empty\n", t);
    } else {
        bpf_printk("(mkdir %d) map1 contains %d at %d\n", t, *data, key);
    }
    return 0;
};

__attribute__((always_inline)) static int mkdir_ret(int t) {
    u32 key = 1;
    u32 value = 42;
    u32 *data = bpf_map_lookup_elem(&map1, &key);
    if (data == NULL) {
        bpf_printk("(mkdirat ret %d) inserting %d at %d in map1\n", t, value, key);
        bpf_map_update_elem(&map1, &key, &value, BPF_ANY);
    } else {
        bpf_printk("(mkdirat ret %d) data already there, nothing to do\n", t);
    }
    return 0;
};

SEC("kprobe/mkdir")
int kprobe_mkdir(void *ctx) {
    return mkdir(1);
}

SEC("kprobe/mkdirat")
int kprobe_mkdirat(void *ctx)
{
    return mkdir(2);
}

SEC("kretprobe/mkdir")
int kretprobe_mkdir(void *ctx)
{
    return mkdir_ret(1);
}

SEC("kretprobe/mkdirat")
int kretprobe_mkdirat(void *ctx)
{
    return mkdir_ret(2);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
