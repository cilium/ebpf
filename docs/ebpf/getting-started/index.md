# Getting Started with eBPF in Go

!!! info
		For a high-level understanding of what eBPF is and how it works, please
		see [the eBPF introduction at ebpf.io](https://ebpf.io/what-is-ebpf).
		This guide assumes familiarity with the basic concepts and terminology.

		In this guide, we'll walk you through building and shipping a new,
		eBPF-powered Go application from scratch. However, we'll focus heavily on the Go
		side of things, building on a relatively minimal eBPF C example.

		See the [Further Reading](further-reading)	section for more in-depth resources
		and reference documentation for developing eBPF C programs. Please see the
		[users](/use-cases) section for existing {{ proj }}-powered projects	of varying sizes
		and complexities. 

## Step 1 - Writing and building eBPF C

Let's start out with a simple eBPF program. It consists of a single call to an eBPF
helper function, which redirects all packets from one interface to another based on
the index of the incoming interface.

!!! 

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_xconnect(struct xdp_md *ctx)
{
    return bpf_redirect_map(&xconnect_map, ctx->ingress_ifindex, 0);
}
```

In order to compile the above program, we need to provide search paths for all the included header files. The easiest way to do that is to make a copy of everything under linux/tools/lib/bpf/, however, this will include a lot of unnecessary files. So an alternative is to create a list of dependencies:

```shell
$ clang -MD -MF xconnect.d -target bpf -I ~/linux/tools/lib/bpf -c xconnect.c
```

Now we can make a local copy of only a small number of files specified in xconnect.d and use the following command to compile eBPF code for the local CPU architecture:

```shell
$ clang -target bpf -Wall -O2 -emit-llvm -g -Iinclude -c xconnect.c -o - | \
llc -march=bpf -mcpu=probe -filetype=obj -o xconnect.o
```

The resulting ELF file is what we’d need to provide to our Go library in the next step.

## Step 2 - Writing the Go code

Compiled eBPF programs and maps can be loaded by {{ proj }} with just a few instructions. By adding a struct with ebpf tags we can automate the relocation procedure so that our program knows where to find its map.

```go
spec, err := ebpf.LoadCollectionSpec("ebpf/xconnect.o")
if err != nil {
  panic(err)
}

var objs struct {
	XCProg  *ebpf.Program `ebpf:"xdp_xconnect"`
	XCMap   *ebpf.Map     `ebpf:"xconnect_map"`
}
if err := spec.LoadAndAssign(&objs, nil); err != nil {
	panic(err)
}
defer objs.XCProg.Close()
defer objs.XCMap.Close()
```

Type ebpf.Map has a set of methods that perform standard CRUD operations on the contents of the loaded map:

```go
err = objs.XCMap.Put(uint32(0), uint32(10))

var v0 uint32
err = objs.XCMap.Lookup(uint32(0), &v0)

err = objs.XCMap.Delete(uint32(0))
```

The only step that’s not covered by {{ proj }} is the attachment of programs to network hooks. This, however, can easily be accomplished by any existing netlink library, e.g. `vishvananda/netlink`, by associating a network link with a file descriptor of the loaded program:

```go
link, err := netlink.LinkByName("eth0")
err = netlink.LinkSetXdpFdWithFlags(*link, c.objs.XCProg.FD(), 2)
```

Note that I’m using the SKB_MODE XDP flag to work around the exiting veth driver caveat. Although the native XDP mode is considerably faster than any other eBPF hook, SKB_MODE may not be as fast due to the fact that packet headers have to be pre-parsed by the network stack (see video).

## Step 3 - Code Distribution

At this point everything should have been ready to package and ship our application if it wasn’t for one problem - eBPF code portability. Historically, this process involved copying of the eBPF source code to the target platform, pulling in the required kernel headers and compiling it for the specific kernel version. This problem is especially pronounced for tracing/monitoring/profiling use cases which may require access to pretty much any kernel data structure, so the only solution is to introduce another layer of indirection (see CO-RE).

Network use cases, on the other hand, rely on a relatively small and stable subset of kernel types, so they don’t suffer from the same kind of problems as their tracing and profiling counterparts. Based on what I’ve seen so far, the two most common code packaging approaches are:

- Ship eBPF code together with the required kernel headers, assuming they match the underlying kernel (see Cilium).
- Ship eBPF code and pull in the kernel headers on the target platform.

In both of these cases, the eBPF code is still compiled on that target platform which is an extra step that needs to be performed before the user-space application can start. However, there’s an alternative, which is to pre-compile the eBPF code and only ship the ELF files. This is exactly what can be done with bpf2go, which can embed the compiled code into a Go package. It relies on go generate to produce a new file with compiled eBPF and {{ proj }} skeleton code, the only requirement being the //go:generate instruction. Once generated though, our eBPF program can be loaded with just a few lines (note the absence of any arguments):

```
specs, err := newXdpSpecs()
objs, err := specs.Load(nil)
```

The obvious benefit of this approach is that we no longer need to compile on the target machine and can ship both eBPF and userspace Go code in a single package or Go binary. This is great because it allows us to use our application not only as a binary but also import it into any 3rd party Go applications (see usage example).
