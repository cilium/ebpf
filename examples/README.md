# eBPF Examples

- [kprobe](kprobe/) - Attach a program to the entry or exit of an arbitrary kernel symbol (function).
- [uprobe](uprobe/) - Like a kprobe, but for symbols in userspace binaries (e.g. `bash`).
- [tracepoint](tracepoint/) - Attach a program to predetermined kernel tracepoints.
- Add your use case(s) here!

## How to run

```bash
git clone https://github.com/cilium/ebpf.git
cd examples/[kprobe,uprobe,tracepoint...]
go build . # You will get the executable file and just run it.

# Do not run `go build main.go` directly for the examples of kprobe and uprobe, otherwise you will get errors like "undefined: KProbeExampleObjects".
 
```