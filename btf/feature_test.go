package btf

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestHaveBTF(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBTF)
}

func TestHaveMapBTF(t *testing.T) {
	testutils.CheckFeatureTest(t, haveMapBTF)
}

func TestHaveProgBTF(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgBTF)
}

func TestHaveFuncLinkage(t *testing.T) {
	testutils.CheckFeatureTest(t, haveFuncLinkage)
}

func TestHaveDeclTags(t *testing.T) {
	testutils.CheckFeatureTest(t, haveDeclTags)
}

func TestHaveTypeTags(t *testing.T) {
	testutils.CheckFeatureTest(t, haveTypeTags)
}

func TestHaveEnum64(t *testing.T) {
	testutils.CheckFeatureTest(t, haveEnum64)
}
