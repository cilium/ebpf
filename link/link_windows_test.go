package link

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/go-quicktest/qt"
	"golang.org/x/sys/windows"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/unix"
)

// ntosebpfext has not yet assigned a stable enum value so we can't refer to
// it via that (https://github.com/microsoft/ntosebpfext/issues/152).
//
// See https://github.com/microsoft/ntosebpfext/blob/75ceaac38a0254e44f3219852d79a336d10ad9f3/include/ebpf_ntos_program_attach_type_guids.h
var (
	programTypeProcessGUID = makeGUID(0x22ea7b37, 0x1043, 0x4d0d, [8]byte{0xb6, 0x0d, 0xca, 0xfa, 0x1c, 0x7b, 0x63, 0x8e})
	attachTypeProcessGUID  = makeGUID(0x66e20687, 0x9805, 0x4458, [8]byte{0xa0, 0xdb, 0x38, 0xe2, 0x20, 0xd3, 0x16, 0x85})
)

func testLinkArch(t *testing.T, link Link) {
	// TODO(windows): Are there win specific behaviour we should test?
}

func newRawLink(t *testing.T) (*RawLink, *ebpf.Program) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.WindowsBind,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	})
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(func() { prog.Close() })

	link, err := AttachRawLink(RawLinkOptions{
		Program: prog,
		Attach:  ebpf.AttachWindowsBind,
	})
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(func() { link.Close() })

	return link, prog
}

func TestProcessLink(t *testing.T) {
	array, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.WindowsArray,
		Name:       "process_state",
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	qt.Assert(t, qt.IsNil(err))
	defer array.Close()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: mustResolveProgramType(t, programTypeProcessGUID),
		Name: "process_test",
		Instructions: asm.Instructions{
			// R1 = map
			asm.LoadMapPtr(asm.R1, array.FD()),
			// R2 = key
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -4),
			asm.StoreImm(asm.R2, 0, 0, asm.Word),
			// R3 = value
			asm.Mov.Reg(asm.R3, asm.R2),
			asm.Add.Imm(asm.R3, -4),
			asm.StoreImm(asm.R3, 0, 1, asm.Word),
			// R4 = flags
			asm.Mov.Imm(asm.R4, 0),
			// bpf_map_update_elem(map, key, value, flags)
			asm.WindowsFnMapUpdateElem.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	})
	if errors.Is(err, unix.EINVAL) {
		t.Logf("Got %s: check that ntosebpfext is installed", err)
	}
	qt.Assert(t, qt.IsNil(err))
	defer prog.Close()

	link, err := AttachRawLink(RawLinkOptions{
		Program: prog,
		Attach:  mustResolveAttachType(t, attachTypeProcessGUID),
	})
	qt.Assert(t, qt.IsNil(err))
	defer link.Close()

	qt.Assert(t, qt.IsNil(exec.Command("cmd.exe", "/c", "exit 0").Run()))

	var value uint32
	qt.Assert(t, qt.IsNil(array.Lookup(uint32(0), &value)))
	qt.Assert(t, qt.Equals(value, 1), qt.Commentf("Executing a binary should trigger the program"))

	qt.Assert(t, qt.IsNil(link.Close()))
}

func mustResolveProgramType(tb testing.TB, guid windows.GUID) ebpf.ProgramType {
	tb.Helper()
	programType, err := ebpf.ProgramTypeForGUID(guid.String())
	qt.Assert(tb, qt.IsNil(err))
	return programType
}

func mustResolveAttachType(tb testing.TB, guid windows.GUID) ebpf.AttachType {
	tb.Helper()
	attachType, err := ebpf.AttachTypeForGUID(guid.String())
	qt.Assert(tb, qt.IsNil(err))
	return attachType
}

func makeGUID(data1 uint32, data2 uint16, data3 uint16, data4 [8]byte) windows.GUID {
	return windows.GUID{Data1: data1, Data2: data2, Data3: data3, Data4: data4}
}
