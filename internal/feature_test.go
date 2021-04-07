package internal

import (
	"errors"
	"strings"
	"testing"
)

func TestFeatureTest(t *testing.T) {
	var called bool

	fn := FeatureTest("foo", "1.0", func() error {
		called = true
		return nil
	})

	if called {
		t.Error("Function was called too early")
	}

	err := fn()
	if !called {
		t.Error("Function wasn't called")
	}

	if err != nil {
		t.Error("Unexpected negative result:", err)
	}

	fn = FeatureTest("bar", "2.1.1", func() error {
		return ErrNotSupported
	})

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

	fn = FeatureTest("bar", "2.1.1", func() error {
		return errors.New("foo")
	})

	err1, err2 := fn(), fn()
	if err1 == err2 {
		t.Error("Cached result of unsuccessful execution")
	}
}
