//go:build amd64

package features

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveBPFLinkTracingMulti(t *testing.T) {
	testutils.CheckFeatureTest(t, HaveBPFLinkTracingMulti)
}
