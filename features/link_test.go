package features

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveBPFLinkUprobeMulti(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFLinkUprobeMulti)
}

func TestHaveBPFLinkKprobeMulti(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFLinkKprobeMulti)
}

func TestHaveBPFLinkKprobeSession(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFLinkKprobeSession)
}
