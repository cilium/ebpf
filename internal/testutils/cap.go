package testutils

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/unix"
)

// WithCapabilities runs `fn` with only the given capabilities
// in the effective set. This allows us to assert that certain operations
// only require specific capabilities.
//
// Warning: on non-linux platforms, this function calls through to `fn` without
// side effects.
func WithCapabilities(t testing.TB, caps []int, fn func()) {
	t.Helper()

	if !platform.IsLinux {
		fn()
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	originalCapset, err := unix.Capget()
	if err != nil {
		t.Fatal("Can't get capabilities:", err)
	}

	var newCapset unix.CapUserData
	for _, cap := range caps {
		newCapset.Effective |= 1 << uint(cap)
	}
	newCapset.Permitted = originalCapset.Permitted

	if err := unix.Capset(newCapset); err != nil {
		t.Fatal("Can't set capabilities:", err)
	}

	defer func() {
		if err := unix.Capset(originalCapset); err != nil {
			t.Fatal("Can't restore capabilities:", err)
		}
	}()

	fn()
}
