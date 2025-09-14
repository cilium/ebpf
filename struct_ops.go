package ebpf

import "github.com/cilium/ebpf/btf"

const structOpsValuePrefix = "bpf_struct_ops_"

// getStructMemberIndexByName returns the index of `member` within struct `s` by
// comparing the member name.
func getStructMemberIndexByName(s *btf.Struct, name string) int {
	for idx, m := range s.Members {
		if m.Name == name {
			return idx
		}
	}
	return -1
}
