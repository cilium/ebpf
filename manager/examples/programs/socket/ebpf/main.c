#include "include/bpf.h"
#include "include/bpf_helpers.h"

SEC("socket/sock_filter")
int socket_sock_filter(void *ctx)
{
    bpf_printk("new packet received\n");
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
