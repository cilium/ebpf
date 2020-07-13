#include "include/bpf.h"
#include "include/bpf_helpers.h"

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int tracepoint_sys_enter_mkdirat(void *ctx)
{
    bpf_printk("mkdirat enter (tracepoint)\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
