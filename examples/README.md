# eBPF Examples

* Kprobe - Attach a program to the entry or exit of an arbitrary kernel symbol (function).
  * [kprobe](kprobe/) - Kprobe using bpf2go.
  * [kprobepin](kprobepin/) - Reuse a pinned map for the kprobe example. It assumes the BPF FS is mounted at `/sys/fs/bpf`.
  * [kprobe_percpu](kprobe_percpu/) - Use a `BPF_MAP_TYPE_PERCPU_ARRAY` map.
  * [ringbuffer](ringbuffer/) - Use a `BPF_MAP_TYPE_RINGBUF` map.
* Uprobe - Attach a program to the entry or exit of an arbitrary userspace binary symbol (function).
  * [uretprobe](uretprobe/) - Uretprobe using bpf2go.
* Tracepoint - Attach a program to predetermined kernel tracepoints.
  * [tracepoint_in_c](tracepoint_in_c/) - Tracepoint using bpf2go.
  * [tracepoint_in_go](tracepoint_in_go/) - Tracepoint using the `ebpf.NewProgram` API and Go eBPF assembler.
* Add your use case(s) here!

## How to run

```bash
cd ebpf/examples/
go run -exec sudo [./kprobe, ./uretprobe, ./ringbuffer, ...]
```
