package link

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
)

// windowsProgramTypeForGUID resolves a GUID to a ProgramType.
func windowsProgramTypeForGUID(tb testing.TB, guid windows.GUID) ebpf.ProgramType {
	programType, err := ebpf.WindowsProgramTypeForGUID(guid.String())
	if errors.Is(err, os.ErrNotExist) {
		tb.Skipf("Attach type not found for GUID %v", guid)
	}
	qt.Assert(tb, qt.IsNil(err))
	return programType
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
