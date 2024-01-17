// Package btf handles data encoded according to the BPF Type Format.
//
// The canonical documentation lives in the Linux kernel repository and is
// available at https://www.kernel.org/doc/html/latest/bpf/btf.html
package btf

// Regenerate btf_gen_types.go by invoking go generate in the current directory.

//go:generate go run github.com/cilium/ebpf/btf/cmd/genbtftypes testdata/vmlinux.btf.gz
