package internal

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/testutils/testmain"
)

func TestMain(m *testing.M) {
	testmain.Run(m)
}

func TestFeatureTest(t *testing.T) {
	var called bool

	fn := NewFeatureTest("foo", func() error {
		called = true
		return nil
	}, "1.0")

	if called {
		t.Error("Function was called too early")
	}

	err := fn()
	if errors.Is(err, ErrNotSupportedOnOS) {
		qt.Assert(t, qt.IsFalse(called))
		return
	}

	qt.Assert(t, qt.IsTrue(called), qt.Commentf("function should be invoked"))

	if err != nil {
		t.Error("Unexpected negative result:", err)
	}

	fn = NewFeatureTest("bar", func() error {
		return ErrNotSupported
	}, "2.1.1")

	err = fn()
	if err == nil {
		t.Fatal("Unexpected positive result")
	}

	fte, ok := err.(*UnsupportedFeatureError)
	if !ok {
		t.Fatal("Result is not a *UnsupportedFeatureError")
	}

	if !strings.Contains(fte.Error(), "2.1.1") {
		t.Error("UnsupportedFeatureError.Error doesn't contain version")
	}

	if !errors.Is(err, ErrNotSupported) {
		t.Error("UnsupportedFeatureError is not ErrNotSupported")
	}

	err2 := fn()
	if err != err2 {
		t.Error("Didn't cache an error wrapping ErrNotSupported")
	}

	fn = NewFeatureTest("bar", func() error {
		return errors.New("foo")
	}, "2.1.1")

	err1, err2 := fn(), fn()
	if err1 == err2 {
		t.Error("Cached result of unsuccessful execution")
	}
}

func TestFeatureTestNotSupportedOnOS(t *testing.T) {
	sentinel := errors.New("quux")
	fn := func() error { return sentinel }

	qt.Assert(t, qt.IsNotNil(NewFeatureTest("foo", fn)()))
	qt.Assert(t, qt.ErrorIs(NewFeatureTest("foo", fn, "froz:1.0.0")(), ErrNotSupportedOnOS))
	qt.Assert(t, qt.ErrorIs(NewFeatureTest("foo", fn, runtime.GOOS+":1.0")(), sentinel))
	if platform.IsLinux {
		qt.Assert(t, qt.ErrorIs(NewFeatureTest("foo", fn, "1.0")(), sentinel))
	}
}

func TestErrNotPermitted(t *testing.T) {
	// ErrNotPermitted should be distinct from ErrNotSupported
	qt.Assert(t, qt.Not(qt.ErrorIs(ErrNotPermitted, ErrNotSupported)))
	qt.Assert(t, qt.Not(qt.ErrorIs(ErrNotSupported, ErrNotPermitted)))

	// Wrapped errors should be matchable
	wrapped := fmt.Errorf("%w: some details", ErrNotPermitted)
	qt.Assert(t, qt.ErrorIs(wrapped, ErrNotPermitted))
	qt.Assert(t, qt.Not(qt.ErrorIs(wrapped, ErrNotSupported)))
}
