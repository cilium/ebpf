package token

import (
	"sync"
	"testing"
)

func TestGlobalTokenDefault(t *testing.T) {
	// Reset to default state for test isolation
	globalTokenFD.Store(-1)

	if got := GetGlobalToken(); got != -1 {
		t.Errorf("GetGlobalToken() = %d, want -1", got)
	}
}

func TestSetGetGlobalToken(t *testing.T) {
	// Reset to default state
	globalTokenFD.Store(-1)

	SetGlobalToken(42)
	if got := GetGlobalToken(); got != 42 {
		t.Errorf("GetGlobalToken() = %d, want 42", got)
	}

	SetGlobalToken(100)
	if got := GetGlobalToken(); got != 100 {
		t.Errorf("GetGlobalToken() = %d, want 100", got)
	}

	// Clear token
	SetGlobalToken(-1)
	if got := GetGlobalToken(); got != -1 {
		t.Errorf("GetGlobalToken() = %d, want -1", got)
	}
}

func TestGlobalTokenConcurrent(t *testing.T) {
	// Reset to default state
	globalTokenFD.Store(-1)

	const numGoroutines = 100
	const numIterations = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Half the goroutines write
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				SetGlobalToken(id)
			}
		}(i)
	}

	// Half the goroutines read
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				_ = GetGlobalToken()
			}
		}()
	}

	wg.Wait()

	// If we got here without a race detector complaint, the test passed.
	// The final value is non-deterministic, but should be valid.
	got := GetGlobalToken()
	if got < -1 || got >= numGoroutines {
		t.Errorf("GetGlobalToken() = %d, want value in range [-1, %d)", got, numGoroutines)
	}
}
