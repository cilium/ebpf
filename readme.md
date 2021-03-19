eBPF
-------
[![](https://godoc.org/github.com/DataDog/ebpf?status.svg)](https://godoc.org/github.com/DataDog/ebpf)

NOTE: This is a fork from [cilium/ebpf](https://github.com/cilium/ebpf) that adds a declarative manager on top to manage the lifecycle of eBPF objects. 

## Current status

Work is underway to convert this library to wrap the upstream library, rather than forking.

## Requirements

* A version of Go that is [supported by upstream](https://golang.org/doc/devel/release.html#policy)
* Linux 4.4+

## Useful resources

* [Upstream library](https://github.com/cilium/ebpf)
* [Cilium eBPF documentation](https://cilium.readthedocs.io/en/latest/bpf/#bpf-guide) (recommended)
* [Linux documentation on BPF](http://elixir.free-electrons.com/linux/latest/source/Documentation/networking/filter.txt)
* [eBPF features by Linux version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
