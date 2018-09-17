eBPF
-------
[![](https://godoc.org/github.com/newtools/ebpf?status.svg)](http://godoc.org/github.com/newtools/ebpf)

eBPF is a Go library that provides utilities for loading, compiling, and debugging eBPF programs. It has minimal external dependencies and is intended to be used in long
running processes.

## An Important Note About Licenses:

The main part of this code is governed by an MIT license. However, the examples folder is a near
straight port of the Linux [eBPF samples folder](http://elixir.free-electrons.com/linux/latest/source/samples/bpf),
which makes that code governed by GPLv2, so be careful if you copy from it heavily as you are likely
pinning yourself to GPLv2.

## Further reading

* [Linux documentation on BPF](http://elixir.free-electrons.com/linux/latest/source/Documentation/networking/filter.txt)
* [Cilium eBPF documentation](http://cilium.readthedocs.io/en/doc-1.0/bpf/) (recommended)
* [eBPF features by Linux version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
