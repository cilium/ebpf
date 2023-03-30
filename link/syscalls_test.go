package link

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveProgAttach(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgAttach)
}

func TestHaveProgAttachReplace(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgAttachReplace)
}

func TestHaveBPFLink(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFLink)
}
