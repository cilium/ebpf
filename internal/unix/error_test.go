package unix

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal"
)

func TestErrNonLinux(t *testing.T) {
	err := errNonLinux()
	qt.Assert(t, qt.StringContains(err.Error(), t.Name()))
	qt.Assert(t, qt.ErrorIs(err, internal.ErrNotSupportedOnOS))
}
