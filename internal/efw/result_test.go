//go:build windows

package efw

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestResultToError(t *testing.T) {
	qt.Assert(t, qt.IsNil(ResultToError(EBPF_SUCCESS)))
	qt.Assert(t, qt.IsNotNil(ResultToError(EBPF_ACCESS_DENIED)))
}
