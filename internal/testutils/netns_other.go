//go:build !linux

// This file is a stub to allow netns to be compiled on non-Linux platforms.
package testutils

import "testing"

type NetNS struct {
}

func NewNetNS(tb testing.TB) *NetNS {
	tb.Helper()
	return &NetNS{}
}

func (h *NetNS) Do(f func() error) error {
	return f()
}
