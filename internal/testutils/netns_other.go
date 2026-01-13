//go:build !linux

// This file is a stub to allow netns to be compiled on non-Linux platforms.
package testutils

import (
	"testing"

	"github.com/cilium/ebpf/internal"
)

type NetNS struct {
}

func NewNetNS(tb testing.TB) *NetNS {
	return nil
}

func (h *NetNS) Do(f func() error) error {
	return internal.ErrNotSupportedOnOS
}
