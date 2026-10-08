//go:build linux

package examples

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func DocVerifierError() {
	// This program is rejected: it exits without initializing R0,
	// the register holding the return value.
	_, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.Return(),
		},
		License: "MIT",
	})

	ve, ok := errors.AsType[*ebpf.VerifierError](err)
	if !ok {
		// Not a VerifierError.
		return
	}

	// Only use the typed (`ve`) error for formatting, never plain `err`! The
	// `error` interface returned by most functions doesn't implement the
	// formatting verbs below.

	// Single-line summary, equivalent to %s or err.Error().
	fmt.Printf("%v\n", ve)

	// The full verifier log, followed by diagnostics and stats.
	fmt.Printf("%+v\n", ve)

	// The first 5 or last 10 log lines, followed by diagnostics and stats.
	fmt.Printf("%+5v\n", ve)
	fmt.Printf("%-10v\n", ve)

	// Only the human-readable diagnostics, if any.
	fmt.Printf("%d\n", ve)
}
