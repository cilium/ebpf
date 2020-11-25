package link

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveProgAttach(t *testing.T) {
	testutils.CheckFeatureTest(t, featureProgAttach)
}

func TestHaveProgAttachReplace(t *testing.T) {
	testutils.CheckFeatureTest(t, featureProgAttachReplace)
}

func TestHaveBPFLink(t *testing.T) {
	testutils.CheckFeatureTest(t, featureBPFLink)
}
