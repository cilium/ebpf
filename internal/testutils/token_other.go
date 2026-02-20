//go:build !linux

package testutils

import (
	"testing"

	"github.com/cilium/ebpf/internal"
)

func RunWithToken(tb testing.TB, delegated Delegated) bool {
	tb.Skip(internal.ErrNotSupportedOnOS)
	return false
}
