package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestTraceFentry(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.5", "BPF_TRACE_FENTRY API")

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachTraceFEntry,
		AttachTo:   "inet_dgram_connect",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	link, err := AttachTrace(prog)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
		loadPinned: func(s string, opts *ebpf.LoadPinOptions) (Link, error) {
			return LoadPinnedTrace(s, opts)
		},
	})

	err = link.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestTraceFexit(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.5", "BPF_TRACE_FEXIT API")

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachTraceFExit,
		AttachTo:   "inet_dgram_connect",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	link, err := AttachTrace(prog)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
		loadPinned: func(s string, opts *ebpf.LoadPinOptions) (Link, error) {
			return LoadPinnedTrace(s, opts)
		},
	})

	err = link.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestTraceFmod(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.5", "BPF_MODIFY_RETURN API")

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachModifyReturn,
		AttachTo:   "bpf_modify_return_test",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	link, err := AttachTrace(prog)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
		loadPinned: func(s string, opts *ebpf.LoadPinOptions) (Link, error) {
			return LoadPinnedTrace(s, opts)
		},
	})

	err = link.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestTraceRawTP(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.5", "BPF_TRACE_RAW_TP API")

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachTraceRawTp,
		AttachTo:   "kfree_skb",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	link, err := AttachTrace(prog)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
		loadPinned: func(s string, opts *ebpf.LoadPinOptions) (Link, error) {
			return LoadPinnedTraceRawTP(s, opts)
		},
	})

	err = link.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestLSM(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.7", "BPF_LSM_MAC API")

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.LSM,
		AttachType: ebpf.AttachLSMMac,
		AttachTo:   "file_mprotect",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	link, err := AttachLSM(prog)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
		loadPinned: func(s string, opts *ebpf.LoadPinOptions) (Link, error) {
			return LoadPinnedTrace(s, opts)
		},
	})

	err = link.Close()
	if err != nil {
		t.Fatal(err)
	}
}
