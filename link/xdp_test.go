package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

const IfIndexLO = 1

func TestAttachXDP(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "BPF_LINK_TYPE_XDP")

	prog := mustLoadProgram(t, ebpf.XDP, 0, "")

	l, err := AttachXDP(XDPOptions{
		Program:   prog,
		Interface: IfIndexLO,
	})
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, l, prog)
}
