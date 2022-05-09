package internal

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/internal/unix"
)

func TestErrorWithLog(t *testing.T) {
	b := []byte("unreachable insn 28")
	b = append(b,
		0xa,  // \n
		0xd,  // \r
		0x9,  // \t
		0x20, // space
		0, 0, // trailing NUL bytes
	)

	err := ErrorWithLog(errors.New("test"), b, unix.ENOSPC)

	want := "test: unreachable insn 28 (truncated...)"
	got := err.Error()

	t.Log(got)

	if want != got {
		t.Fatalf("\nwant: %s\ngot: %s", want, got)
	}
}
