package link

import (
	"io"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestIter(t *testing.T) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachTraceIter,
		AttachTo:   "bpf_map",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't load program:", err)
	}
	defer prog.Close()

	it, err := AttachIter(IterOptions{
		Program: prog,
	})
	if err != nil {
		t.Fatal("Can't create iter:", err)
	}

	file, err := it.Open()
	if err != nil {
		t.Fatal("Can't open iter instance:", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	if len(contents) != 0 {
		t.Error("Non-empty output from no-op iterator:", string(contents))
	}

	testLink(t, it, testLinkOptions{
		prog: prog,
		loadPinned: func(s string, opts *ebpf.LoadPinOptions) (Link, error) {
			return LoadPinnedIter(s, opts)
		},
	})
}

func TestIterMapElements(t *testing.T) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachTraceIter,
		AttachTo:   "bpf_map_elem",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't load program:", err)
	}
	defer prog.Close()

	arr, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer arr.Close()

	it, err := AttachIter(IterOptions{
		Program: prog,
		Map:     arr,
	})
	if err != nil {
		t.Fatal("Can't create iter:", err)
	}
	defer it.Close()

	file, err := it.Open()
	if err != nil {
		t.Fatal("Can't open iter instance:", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	if len(contents) != 0 {
		t.Error("Non-empty output from no-op iterator:", string(contents))
	}
}
