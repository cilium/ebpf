#include "include/bpf.h"
#include "include/bpf_map.h"
#include "include/bpf_helpers.h"

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

__attribute__((always_inline)) static u64 load_my_constant() {
    u64 my_constant = 0;
    LOAD_CONSTANT("my_constant", my_constant);
    return my_constant;
}

struct bpf_map_def SEC("maps/my_constants") my_constants = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(void *ctx)
{
    u64 my_constant = load_my_constant();
    bpf_printk("mkdir (vfs hook point) | my_constant = %d\n", load_my_constant());

    // Send my constant to user space
    u32 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &my_constants, cpu, &my_constant, sizeof(my_constant));
    return 0;
};

SEC("kprobe/vfs_rmdir")
int kprobe_vfs_rmdir(void *ctx)
{
    u64 my_constant = load_my_constant();
    bpf_printk("rmdir (vfs hook point) | my_constant = %d\n", load_my_constant());

    // Send my constant to user space
    u32 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &my_constants, cpu, &my_constant, sizeof(my_constant));
    return 0;
};

SEC("kretprobe/mkdir")
int kretpobe_mkdir(void *ctx)
{
    bpf_printk("mkdir return (syscall hook point)\n");
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
