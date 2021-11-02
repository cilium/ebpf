#define STRSZ 100 + 1

#include "common.h"
#include "bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event_t {
    char filename[STRSZ];
    char fn_name[STRSZ];
};

SEC("uprobe/python/function__entry")
int handler(struct pt_regs *ctx) {
    struct event_t event = {};

    /*
    Displaying notes found in: .note.stapsdt
    Owner                Data size 	Description
    stapsdt              0x00000045	NT_STAPSDT (SystemTap probe descriptors)
        Provider: python
        Name: function__entry
        Location: 0x00000000000667d3, Base: 0x000000000029c250, Semaphore: 0x0000000000332d6e
        Arguments: 8@%r14 8@%r15 -4@%eax
    */
    bpf_probe_read_user_str(event.filename, STRSZ, (void *)ctx->r14);
    bpf_probe_read_user_str(event.fn_name, STRSZ, (void *)ctx->r15);
    bpf_ringbuf_output(&events, &event, sizeof(struct event_t), 0);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
