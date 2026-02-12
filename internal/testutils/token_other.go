//go:build !linux

package testutils

import (
	"testing"

	"github.com/cilium/ebpf/internal"
)

func RunWithToken(t *testing.T, name string, delegated Delegated, fn func(t *testing.T)) {
	t.Skip(internal.ErrNotSupportedOnOS)
}
