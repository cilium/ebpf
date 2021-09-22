# eBPF Examples

* Kprobe - Attach a program to the entry or exit of an arbitrary kernel symbol (function).
  * [kprobe](kprobe/) - Kprobe on `sys_execve` using bpf2go.
  * [kprobepin](kprobepin/) - Reuse a pinned map for the kprobe example. It assumes the BPF FS is mounted at `/sys/fs/bpf`.
  * [kprobe_percpu](kprobepin/) - Use a `BPF_MAP_TYPE_PERCPU_ARRAY` map.
  * [ringbuffer](ringbuffer/) - Use a `BPF_MAP_TYPE_RINGBUF` map.
* Uprobe - Attach a program to the entry or exit of an arbitrary userspace binary symbol (function).
  * [uretprobe](uretprobe/) - Uretprobe on `bash::readline`.
* Tracepoint - Attach a program to predetermined kernel tracepoints.
  * [tracepoint_in_c](tracepoint_in_c/) - Tracepoint on `kmem/mm_page_alloc` using bpf2go.
  * [tracepoint_in_go](tracepoint_in_go/) - Tracepoint on `syscalls/sys_enter_openat` using the `ebpf.NewProgram` API.
* Add your use case(s) here!

## How to run

```bash
cd ebpf/examples/
go run -exec sudo [./kprobe, ./uretprobe, ./ringbuffer, ...]
```
