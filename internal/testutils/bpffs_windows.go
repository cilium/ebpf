package testutils

import (
	"errors"
	"math/rand"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/efw"
)

// TempBPFFS creates a random prefix to use when pinning on Windows.
func TempBPFFS(tb testing.TB) string {
	tb.Helper()

	path := filepath.Join("ebpf-go-test", strconv.Itoa(rand.Int()))
	path, err := efw.EbpfCanonicalizePinPath(path)
	qt.Assert(tb, qt.IsNil(err))

	tb.Cleanup(func() {
		tb.Helper()

		cursor := path
		for {
			next, _, err := efw.EbpfGetNextPinnedObjectPath(cursor, efw.EBPF_OBJECT_UNKNOWN)
			if errors.Is(err, efw.EBPF_NO_MORE_KEYS) {
				break
			}
			qt.Assert(tb, qt.IsNil(err))

			if !strings.HasPrefix(next, path) {
				break
			}

			if err := efw.EbpfObjectUnpin(next); err != nil {
				tb.Errorf("Failed to unpin %s: %s", next, err)
			}

			cursor = next
		}
	})

	return path
}
