package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestProgramAlter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.13", "SkSKB type")

	var err error
	var prog *ebpf.Program
	prog, err = ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SkSKB,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	var sockMap *ebpf.Map
	sockMap, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.MapType(15), // BPF_MAP_TYPE_SOCKMAP
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sockMap.Close()

	err = RawAttachProgram(RawAttachProgramOptions{
		Target:  sockMap.FD(),
		Program: prog,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = RawDetachProgram(RawDetachProgramOptions{
		Target:  sockMap.FD(),
		Program: prog,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		t.Fatal(err)
	}
}
