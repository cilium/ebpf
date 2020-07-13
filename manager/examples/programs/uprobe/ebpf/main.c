#include "include/bpf.h"
#include "include/bpf_helpers.h"

SEC("uprobe/readline")
int uprobe_readline(void *ctx)
{
    bpf_printk("new bash command detected\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
