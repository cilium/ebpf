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
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	l, err := AttachXDP(XDPOptions{
		Program:   prog,
		Interface: "lo",
		Flags:     XDPGenericMode,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = l.Close()
	if err != nil {
		t.Fatal(err)
	}

	l, err = AttachXDP(XDPOptions{
		Program:   prog,
		Interface: IfIndexLO,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = l.Close()
	if err != nil {
		t.Fatal(err)
	}

	// test unknown interface name
	_, err = AttachXDP(XDPOptions{Program: prog, Interface: "unknown"})
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}
