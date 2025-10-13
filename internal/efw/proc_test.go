//go:build windows

package efw

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestNewProc(t *testing.T) {
	_, err := newProc("a_function_which_doesnt_exist").Find()
	qt.Assert(t, qt.ErrorMatches(err, ".* a_function_which_doesnt_exist .*"))
}

func TestCall(t *testing.T) {
	var err error
	allocs := testing.AllocsPerRun(10, func() {
		_, err = EbpfGetEbpfAttachType(2)
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(allocs, 0))
}
