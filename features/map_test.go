package features

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestHaveMapType(t *testing.T) {
	for mt := ebpf.UnspecifiedMap + 1; mt < ebpf.MaxMapType; mt++ {
		err := HaveMapType(mt)
		if err != nil {
			t.Logf("%s: %v", mt.String(), err)
		}
	}

}
