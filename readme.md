eBPF
-------
[![](https://godoc.org/github.com/newtools/ebpf?status.svg)](http://godoc.org/github.com/newtools/ebpf)

eBPF is go library that provides utilities for loading, compiling, and debugging eBPF programs.

* Object pinning and loading
* bpf-to-bpf calls
* Map of maps
* Per CPU maps
* Rewriting of constants

## An Important Note About Licenses:
If you are using this project for your own internal monitoring or using it to provide a service,
then you (probably) do not need to read the rest of this note. However, if you are planning to
use this project to distribute software you should read on.

The main part of this code is governed by an MIT license. However, the examples folder is a near
straight port of the Linux [eBPF samples folder](http://elixir.free-electrons.com/linux/latest/source/samples/bpf),
which makes that code governed by GPLv2, so be careful if you copy from it heavily as you are likely
pinning yourself to GPLv2. However, eBPF opcode programs themselves must be governed by the GPLv2 anyways,
so if you are distributing any software relying on this project you will probably be open-sourcing the most
important part (the eBPF opcode) anyways.

## Further reading

* [Linux documentation on BPF](http://elixir.free-electrons.com/linux/latest/source/Documentation/networking/filter.txt)
* [Cilium eBPF documentation](http://cilium.readthedocs.io/en/doc-1.0/bpf/) (recommended)
* [eBPF features by Linux version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
