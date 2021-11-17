package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestProgramAlter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.13", "SkSKB type")

	prog := mustLoadProgram(t, ebpf.SkSKB, 0, "")

	var sockMap *ebpf.Map
	sockMap, err := ebpf.NewMap(&ebpf.MapSpec{
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
