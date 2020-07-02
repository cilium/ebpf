package internal

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestFeatureTest(t *testing.T) {
	var called bool

	fn := FeatureTest("foo", "1.0", func() (bool, error) {
		called = true
		return true, nil
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

	fn = FeatureTest("bar", "2.1.1", func() (bool, error) {
		return false, nil
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

	fn = FeatureTest("bar", "2.1.1", func() (bool, error) {
		return false, errors.New("foo")
	})

	err1, err2 := fn(), fn()
	if err1 == err2 {
		t.Error("Cached result of unsuccessful execution")
	}

	fn = FeatureTest("bar", "2.1.1", func() (bool, error) {
		return false, fmt.Errorf("bar: %w", ErrNotSupported)
	})

	err1, err2 = fn(), fn()
	if err1 != err2 {
		t.Error("Didn't cache an error wrapping ErrNotSupported")
	}
}

func TestVersion(t *testing.T) {
	a, err := NewVersion("1.2")
	if err != nil {
		t.Fatal(err)
	}

	b, err := NewVersion("2.2.1")
	if err != nil {
		t.Fatal(err)
	}

	if !a.Less(b) {
		t.Error("A should be less than B")
	}

	if b.Less(a) {
		t.Error("B shouldn't be less than A")
	}

	v200 := Version{2, 0, 0}
	if !a.Less(v200) {
		t.Error("1.2.1 should not be less than 2.0.0")
	}

	if v200.Less(a) {
		t.Error("2.0.0 should not be less than 1.2.1")
	}
}
