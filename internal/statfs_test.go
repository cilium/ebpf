package internal

import (
	"testing"

	"github.com/cilium/ebpf/internal/unix"

	"github.com/go-quicktest/qt"
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
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(fst, fs.magic))
	}
}
