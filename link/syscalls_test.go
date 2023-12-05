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

func TestHaveProgQuery(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgQuery)
}

func TestHaveTCX(t *testing.T) {
	testutils.CheckFeatureTest(t, haveTCX)
}

func TestHaveNetkit(t *testing.T) {
	testutils.CheckFeatureTest(t, haveNetkit)
}
