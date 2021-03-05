// Program bpf2go embeds eBPF in Go.
//
// It compiles a C source file into eBPF bytecode and then emits a
// Go file containing the eBPF. The goal is to avoid loading the
// eBPF from disk at runtime and to minimise the amount of manual
// work required to interact with eBPF programs. It takes inspiration
// from `bpftool gen skeleton`.
//
// Invoke the program using go generate:
//    //go:generate go run github.com/cilium/ebpf/cmd/bpf2go foo path/to/src.c -- -I/path/to/include
// This will emit foo_bpfel.go and foo_bpfeb.go, with types using `foo`
// as a stem. The two files contain compiled BPF for little and big
// endian systems, respectively.
//
// You can use environment variables to affect all bpf2go invocations
// across a project, e.g. to set specific C flags:
//    //go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "$BPF_CFLAGS" foo path/to/src.c
// By exporting $BPF_CFLAGS from your build system you can then control
// all builds from a single location.
//
// Requires at least clang 9.
//
// For a full list of accepted options check the `-help` output. There is a
// fully working example at https://github.com/cilium/ebpf/blob/master/cmd/bpf2go/example_test.go.
package main
