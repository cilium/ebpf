package features

import (
	"testing"

	"github.com/cilium/ebpf/internal/token"
)

func TestGlobalTokenWrapper(t *testing.T) {
	// Reset to default state
	token.SetGlobalToken(-1)

	// Test that the features package correctly wraps internal/token
	if got := GetGlobalToken(); got != -1 {
		t.Errorf("GetGlobalToken() = %d, want -1", got)
	}

	SetGlobalToken(123)
	if got := GetGlobalToken(); got != 123 {
		t.Errorf("GetGlobalToken() = %d, want 123", got)
	}

	// Verify internal package sees the same value
	if got := token.GetGlobalToken(); got != 123 {
		t.Errorf("token.GetGlobalToken() = %d, want 123", got)
	}

	// Clean up
	SetGlobalToken(-1)
}
