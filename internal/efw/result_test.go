//go:build windows

package efw

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestResultToError(t *testing.T) {
	qt.Assert(t, qt.IsNil(resultToError(EBPF_SUCCESS)))
	qt.Assert(t, qt.IsNotNil(resultToError(EBPF_ACCESS_DENIED)))

	// Ensure that common results do not allocate.
	for _, result := range []Result{
		EBPF_SUCCESS,
		EBPF_NO_MORE_KEYS,
		EBPF_KEY_NOT_FOUND,
	} {
		t.Run(result.String(), func(t *testing.T) {
			allocs := testing.AllocsPerRun(1, func() {
				_ = resultToError(result)
			})
			qt.Assert(t, qt.Equals(allocs, 0.0))
		})
	}
}
