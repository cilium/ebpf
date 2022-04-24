# `tcpconnlat`: measure TCP connect latency

This example traces TCP connect events and measures the connecting latency.
References for the implementation:

1. cilium/ebpf: [examples/tcprtt](../tcprtt)
2. bcc tool: [`tcpconnlat`](https://github.com/iovisor/bcc/blob/master/tools/tcpconnlat.py)

## Run

Run directly with `go run`:

```shell
$ cd cilium/ebpf/examples
$ go run -exec sudo ./tcpconnlat
```

Or, you could compile it and run the binary:

```shell
$ cd cilium/ebpf/examples/tcpconnlat && go build
$ ls
bpf_bpfeb.go  bpf_bpfeb.o  bpf_bpfel.go  bpf_bpfel.o  main.go  README.md  tcpconnlat  tcpconnlat.c

$ sudo ./tcpconnlat
```

## Test

Start the program, then creat several TCP connections, for example:

```shell
$ curl example.com
$ curl trip.com
$ curl localhost:8000
```

The output:

```
$ sudo ./tcpconnlat
2022/04/24 15:10:05 Attaching BPF program TcpRcvStateProcess Tracing(tcp_rcv_state_process)#6
2022/04/24 15:10:05 Attaching BPF program TcpV4Connect Tracing(tcp_v4_connect)#10
2022/04/24 15:10:05 Src addr        Port   -> Dest addr       Port   Latency (us)
2022/04/24 15:10:15 10.0.2.15       63695  -> 93.184.216.34   80     173441
2022/04/24 15:10:25 10.0.2.15       42738  -> 103.158.15.7    80     126886
2022/04/24 15:10:37 127.0.0.1       51334  -> 127.0.0.1       8000   45
^C2022/04/24 15:10:39 Received signal, exiting..
```

## Debug

Print messages with `bpf_printk()`, for example:

```c
    bpf_printk("tcp_v4_connect latency_us: %u", latency_us);
```

Then re-compile and re-run the program:

```shell
$ cd cilium/ebpf/examples
$ make generate

$ go run -exec sudo ./tcpconnlat
```

The output in system trace pipe:

```shell
$ sudo tail /sys/kernel/debug/tracing/trace
          <idle>-0       [003] d.s. 1224122.560822: bpf_trace_printk: tcp_v4_connect latency_us: 69
          <idle>-0       [003] d.s. 1224235.450321: bpf_trace_printk: tcp_v4_connect latency_us: 29979
```
