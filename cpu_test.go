package ebpf

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestPossibleCPU(t *testing.T) {
	num, err := PossibleCPU()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(num > 0))
}
