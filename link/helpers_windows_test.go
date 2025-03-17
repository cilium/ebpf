package link

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/platform"
)

// windowsProgramTypeForGUID resolves a GUID to a ProgramType.
func windowsProgramTypeForGUID(tb testing.TB, guid windows.GUID) ebpf.ProgramType {
	rawProgramType, err := efw.EbpfGetBpfProgramType(guid)
	qt.Assert(tb, qt.IsNil(err))

	if rawProgramType == 0 {
		tb.Skipf("Program type not found for GUID %v", guid)
	}

	typ, err := ebpf.ProgramTypeForPlatform(platform.Windows, rawProgramType)
	qt.Assert(tb, qt.IsNil(err))
	return typ
}

// windowsAttachTypeForGUID resolves a GUID to an AttachType.
func windowsAttachTypeForGUID(tb testing.TB, guid windows.GUID) ebpf.AttachType {
	attachType, err := ebpf.WindowsAttachTypeForGUID(guid.String())
	if errors.Is(err, os.ErrNotExist) {
		tb.Skipf("Attach type not found for GUID %v", guid)
	}
	qt.Assert(tb, qt.IsNil(err))
	return attachType
}
