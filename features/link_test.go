package features

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveBPFLinkUprobeMulti(t *testing.T) {
	testutils.CheckFeatureTest(t, HaveBPFLinkUprobeMulti)
}

func TestHaveBPFLinkKprobeMulti(t *testing.T) {
	testutils.CheckFeatureTest(t, HaveBPFLinkKprobeMulti)
}

func TestHaveBPFLinkKprobeSession(t *testing.T) {
	testutils.CheckFeatureTest(t, HaveBPFLinkKprobeSession)
}
