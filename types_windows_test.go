package ebpf

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"
	"golang.org/x/sys/windows"
)

func TestWindowsAttachTypeForGUID(t *testing.T) {
	xdpGUID := windows.GUID{
		Data1: 0x85e0d8ef, Data2: 0x579e, Data3: 0x4931,
		Data4: [...]byte{0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d},
	}

	_, err := WindowsAttachTypeForGUID("{00000000-0000-0000-0000-000000000001}")
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))

	attachType, err := WindowsAttachTypeForGUID(xdpGUID.String())
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(AttachWindowsXDP, attachType))
}
