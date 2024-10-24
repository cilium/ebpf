//go:build linux

package linux

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestCurrentKernelVersion(t *testing.T) {
	_, err := KernelVersion()
	qt.Assert(t, qt.IsNil(err))
}

func TestKernelRelease(t *testing.T) {
	r, err := KernelRelease()
	if err != nil {
		t.Fatal(err)
	}

	if r == "" {
		t.Fatal("unexpected empty kernel release")
	}
}
