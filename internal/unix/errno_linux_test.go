package unix

import (
	"testing"

	"github.com/go-quicktest/qt"
	"golang.org/x/sys/unix"
)

func TestErrnoIsUnix(t *testing.T) {
	qt.Assert(t, qt.ErrorIs(EPERM, unix.EPERM))
	qt.Assert(t, qt.ErrorIs(ENOENT, unix.ENOENT))
}
