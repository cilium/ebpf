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

/**
 * routed_cache is used to define the types of maps that are expected in maps_router
 * WARNING: it has to be the first map defined in the `maps/maps_router`
 * section since it is referred to as map #0 in maps_router.
 */
struct bpf_map_def SEC("maps/maps_router") routed_cache = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps/maps_router") maps_router = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(u32),
    .max_entries = 10,
    .inner_map_idx = 0, /* map_fd[0] is routed_cache */
};

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(void *ctx)
{
    bpf_printk("(prog2) writing 42 in shared_cache1 at key 1 ...\n");
    // Update the shared cache
    u32 key = 1;
    u32 val = 42;
    bpf_map_update_elem(&shared_cache1, &key, &val, BPF_ANY);

    // Update the routed map
    val = 500;
    void *routed_map = bpf_map_lookup_elem(&maps_router, &key);
    if (routed_map == NULL)
    {
        return 0;
    }
    bpf_printk("(prog2) writing 500 in router_map at key 1 ...\n");
    bpf_map_update_elem(routed_map, &key, &val, BPF_ANY);
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
