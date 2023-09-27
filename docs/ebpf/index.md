# Welcome!

![Honeygopher](ebpf-go.png){ align=right width="200" }

:ebpf-go: {{ proj }} is a Go library for working with :ebee-color: eBPF. It does
not depend on C, libbpf, or any other Go libraries other than the standard
library, making it an excellent choice for writing self-contained, portable
tools that run on a variety of architectures.

This documentation provides a central resource for learning how to build eBPF
applications with the user space component written in Go.

## Target Audience

For a high-level understanding of what eBPF is and how it works, please see [the
eBPF introduction at ebpf.io](https://ebpf.io/what-is-ebpf).

This documentation assumes familiarity with the basic concepts and terminology
of eBPF, as well as a basic understanding of the Go toolchain and how to write
idiomatic Go code.

## Learning More

Discover [more projects using {{ proj }} here](users.md). The main repository
also contains an [examples
directory](https://github.com/cilium/ebpf/tree/main/examples) with minimal demo
applications that can be tested on any supported Linux machine.
