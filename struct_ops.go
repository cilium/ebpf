package ebpf

import "fmt"

// structOpsMeta is a placeholder object inserted into MapSpec.Contents
// so that later stages (loader, ELF parser) can recognise this map as
// a struct‑ops map without adding public fields yet.
type structOpsMeta struct {
	userTypeName string
	kernTypeName string
	members      []struct {
		name     string
		userOfs  uint32
		size     uint32
		kind     uint8
		progName string
	}
	initUserBlob []byte
}

// extractStructOpsMeta returns the *structops.Meta embedded in a MapSpec’s Contents
// according to the struct-ops convention:
//
//	contents[0].Key   == uint32(0)
//	contents[0].Value == *structopsMeta
func extractStructOpsMeta(contents []MapKV) (*structOpsMeta, error) {
	if len(contents) == 0 {
		return nil, fmt.Errorf("struct_ops: missing meta at Contents[0]")
	}

	k, ok := contents[0].Key.(uint32)
	if !ok || k != 0 {
		return nil, fmt.Errorf("struct_ops: meta key must be 0")
	}

	meta, ok := contents[0].Value.(structOpsMeta)
	if !ok {
		return nil, fmt.Errorf("struct_ops: meta value must be structOpsMeta")
	}

	return &meta, nil
}
