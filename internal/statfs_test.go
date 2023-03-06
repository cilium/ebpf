package internal

import (
	"testing"

	"github.com/cilium/ebpf/internal/unix"

	qt "github.com/frankban/quicktest"
)

func TestFSType(t *testing.T) {
	for _, fs := range []struct {
		path  string
		magic int64
	}{
		{"/sys/kernel/tracing", unix.TRACEFS_MAGIC},
		{"/sys/fs/bpf", unix.BPF_FS_MAGIC},
	} {
		fst, err := FSType(fs.path)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, fst, qt.Equals, fs.magic)
	}
}
