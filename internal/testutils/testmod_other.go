//go:build !linux

package testutils

import (
	"testing"

	"github.com/cilium/ebpf/internal"
)

func RequireTestmod(tb testing.TB, reason string) {
	tb.Helper()
	tb.Skip(internal.ErrNotSupportedOnOS)
}
