<style>
  .md-content .md-typeset h1 {
    display: none;
  }
</style>

<p align="center" class="tagline">The eBPF Library for Go</p>

![Honeygopher](ebpf-go.png){ align=right width="180" }

[![PkgGoDev](https://pkg.go.dev/badge/github.com/cilium/ebpf)](https://pkg.go.dev/github.com/cilium/ebpf)

:ebpf-go: {{ proj }} is a Go library for working with :ebee-color: eBPF. It does
not depend on C, libbpf, or any other Go libraries other than the standard
library, making it an excellent choice for writing self-contained, portable
tools that run on a variety of architectures.

This documentation aims to provide a central resource for learning how to build
Go applications that use eBPF.

## Installing

To add {{ proj }} as a dependency to an existing Go module, run this from within
the module's directory:

```
go get github.com/cilium/ebpf
```

## Target Audience

This documentation assumes familiarity with the basic concepts and terminology
of eBPF, as well as a basic understanding of the Go toolchain and how to write
idiomatic Go code.

For a high-level understanding of what eBPF is and how it works, please see [the
eBPF introduction at :ebee-color: ebpf.io](https://ebpf.io/what-is-ebpf).

## Examples

Discover [projects using {{ proj }} here](users.md). The repository contains an
[examples/ directory](https://github.com/cilium/ebpf/tree/main/examples) with
minimal demo applications that can be tested on any supported Linux machine.
