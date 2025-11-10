//go:build ignore

#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Simple fexit program that attaches to the vfs_read kernel function.
// This function is called whenever data is read from a file.
//
// The fexit hook runs after the function completes. We use vfs_read
// because it's stable, widely available, and has good BTF support across
// different kernel versions.
//
// We don't access the parameters, just log that the function was called.
SEC("fexit/vfs_read")
int BPF_PROG(vfs_read_exit)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	
	// Log file reads
	bpf_printk("fexit: vfs_read called by PID %u\n", pid);
	
	return 0;
}
