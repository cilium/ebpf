module github.com/cilium/ebpf/examples

go 1.15

require (
	github.com/cilium/ebpf v0.5.0
	golang.org/x/sys v0.0.0-20210124154548-22da62e12c0c
)

replace github.com/cilium/ebpf v0.5.0 => ../../cebpf // TODO: remove this once https://github.com/cilium/ebpf/pull/279 gets merged
