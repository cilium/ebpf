package testutils

import (
	"testing"
	"time"
)

// WaitChan waits for a value to be sent on a channel, or for a timeout to
// occur. If the timeout is reached, the test will fail.
func WaitChan[T any](tb testing.TB, ch <-chan T, timeout time.Duration) {
	tb.Helper()

	select {
	case <-ch:
		return
	case <-time.After(timeout):
		tb.Fatalf("timeout waiting for channel")
	}
}
