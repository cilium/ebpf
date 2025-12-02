# Examples

A collection of programs showing how to use the library.
Please see our [guide on what makes a good example](https://ebpf-go.dev/contributing/new-example/) if you think something is missing.

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
* Cgroup - Attach a program to control groups (cgroups).
  * [cgroup_skb](cgroup_skb/) - Count packets egressing the current cgroup.
* Fentry - Attach a program to the entrypoint of a kernel function.
  Like kprobes, but with better performance and usability, for kernels 5.5 and later.
  * [tcp_connect](fentry/) - Trace outgoing IPv4 TCP connections.
  * [tcp_close](tcprtt/) - Log RTT of IPv4 TCP connections using eBPF CO-RE helpers.
* TCx - Attach a program to Linux TC (Traffic Control) to process incoming and outgoing packets.
  * [tcx](./tcx/) - Print packet counts for ingress and egress.
* XDP - Attach a program to a network interface to process incoming packets.
  * [xdp](xdp/) - Print packet counts by IPv4 source address.
  * [xdp_live_frame](xdp_live_frame/) - XDP-based traffic generator that uses live frame mode.
* sched_ext - Attach a StructOpsMap to register a custom task scheduler. This feature is supported by kernel version starting from version 6.12.
  * [sched_ext](sched_ext/) - Minimal sched_ext_ops.

## How to run

```bash
cd ebpf/examples/
go run -exec sudo [./kprobe, ./uretprobe, ./ringbuffer, ...]
```

## How to recompile

The examples are built via `go generate` invoked by the Makefile in the project root.

```
make -C ../
```
