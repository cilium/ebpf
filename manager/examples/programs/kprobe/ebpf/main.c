#include "include/bpf.h"
#include "include/bpf_helpers.h"

SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(void *ctx)
{
    bpf_printk("mkdir (vfs hook point)\n");
    return 0;
};

SEC("kprobe/utimes_common")
int kprobe_utimes_common(void *ctx)
{
    bpf_printk("utimes_common\n");
    return 0;
};

SEC("kretprobe/mkdirat")
int kretpobe_unlinkat(void *ctx)
{
    bpf_printk("mkdirat return (syscall hook point)\n");
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
