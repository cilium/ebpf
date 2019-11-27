package internal

import "testing"

func TestFeatureTest(t *testing.T) {
	var called bool

	fn := FeatureTest(func() bool {
		called = true
		return true
	})

	if called {
		t.Error("Function was called too early")
	}

	result := fn()
	if !called {
		t.Error("Function wasn't called")
	}

	if !result {
		t.Error("Wrong memoized result")
	}
}
