package link

import (
	"math"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/go-quicktest/qt"
)

const IfIndexLO = 1

func TestAttachXDP(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "BPF_LINK_TYPE_XDP")

	prog := mustLoadProgram(t, ebpf.XDP, 0, "")

	_, err := AttachXDP(XDPOptions{
		Program:   prog,
		Interface: math.MaxInt,
	})
	qt.Assert(t, qt.IsNotNil(err))

	l, err := AttachXDP(XDPOptions{
		Program:   prog,
		Interface: IfIndexLO,
	})
	qt.Assert(t, qt.IsNil(err))

	testLink(t, l, prog)
}
