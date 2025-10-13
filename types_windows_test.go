package ebpf

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"
	"golang.org/x/sys/windows"
)

func TestWindowsProgramTypeForGUID(t *testing.T) {
	sampleGUID := windows.GUID{
		Data1: 0xf788ef4a, Data2: 0x207d, Data3: 0x4dc3,
		Data4: [...]byte{0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c},
	}

	_, err := WindowsProgramTypeForGUID("{00000000-0000-0000-0000-000000000001}")
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))

	programType, err := WindowsProgramTypeForGUID(sampleGUID.String())
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(WindowsSample, programType))
}

func TestWindowsAttachTypeForGUID(t *testing.T) {
	sampleGUID := windows.GUID{
		Data1: 0xf788ef4b, Data2: 0x207d, Data3: 0x4dc3,
		Data4: [...]byte{0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c},
	}

	_, err := WindowsAttachTypeForGUID("{00000000-0000-0000-0000-000000000001}")
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))

	attachType, err := WindowsAttachTypeForGUID(sampleGUID.String())
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(AttachWindowsSample, attachType))
}
