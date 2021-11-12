package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

const IfIndexLO = 1

func TestAttachXDP(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.7", "BPF_LINK_TYPE_XDP")
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 2, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	l, err := AttachXDP(XDPOptions{
		Program:   prog,
		Interface: IfIndexLO,
	})
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, l, testLinkOptions{
		prog: prog,
		loadPinned: func(s string, opts *ebpf.LoadPinOptions) (Link, error) {
			return LoadPinnedRawLink(s, XDPType, opts)
		},
	})

	err = l.Close()
	if err != nil {
		t.Fatal(err)
	}
}
