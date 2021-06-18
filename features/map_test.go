package features

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestProbeMapType(t *testing.T) {
	for mt := ebpf.UnspecifiedMap + 1; mt < ebpf.MaxMapType; mt++ {
		err := ProbeMapType(mt)
		if err != nil {
			t.Logf("%s: %v", mt.String(), err)
		}
	}

}
