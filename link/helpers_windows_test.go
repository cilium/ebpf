package link

import (
	"testing"

	"golang.org/x/sys/windows"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/platform"
)

// windowsProgramTypeFromGUID resolves a GUID to a ProgramType.
func windowsProgramTypeFromGUID(tb testing.TB, guid windows.GUID) ebpf.ProgramType {
	rawProgramType, err := efw.EbpfGetBpfProgramType(guid)
	qt.Assert(tb, qt.IsNil(err))

	if rawProgramType == 0 {
		tb.Skipf("Program type not found for GUID %v", guid)
	}

	typ, err := ebpf.ProgramTypeForPlatform(platform.Windows, rawProgramType)
	qt.Assert(tb, qt.IsNil(err))
	return typ
}

// windowsAttachTypeFromGUID resolves a GUID to an AttachType.
func windowsAttachTypeFromGUID(tb testing.TB, guid windows.GUID) ebpf.AttachType {
	rawAttachType, err := efw.EbpfGetBpfAttachType(guid)
	qt.Assert(tb, qt.IsNil(err))

	if rawAttachType == 0 {
		tb.Skipf("Attach type not found for GUID %v", guid)
	}

	typ, err := ebpf.AttachTypeForPlatform(platform.Windows, rawAttachType)
	qt.Assert(tb, qt.IsNil(err))
	return typ
}
