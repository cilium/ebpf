// Package ebpf is a toolkit for working with eBPF programs.
//
// eBPF programs are small snippets of code which are executed directly
// in a VM in the Linux kernel, which makes them very fast and flexible.
// Many Linux subsystems now accept eBPF programs. This makes it possible
// to implement highly application specific logic inside the kernel,
// without having to modify the actual kernel itself.
//
// Since eBPF is a relatively young concept, documentation and user space
// support is still lacking. Most of the available tools are written in C, and
// reside in the kernel's source tree. The more mature external projects like
// libbcc focus on using eBPF for instrumentation and debugging. This
// leads to certain trade-offs which are not acceptable when
// writing production services.
//
// This package is instead designed for long-running processes which
// want to use eBPF to implement part of their application logic. It has no
// run-time dependencies outside of the library and the Linux kernel itself.
// eBPF code should be compiled ahead of time using clang, and shipped with
// your application as any other resource.
//
// The two main parts are an ELF loader, which reads object files emitted by
// clang, and facilities to modify and load eBPF programs into the kernel.
//
// This package doesn't include code required to attach eBPF to Linux
// subsystems, since this varies per subsystem. See the examples for possible
// solutions.
package ebpf
