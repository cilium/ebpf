package ebpf

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestSanitizeName(t *testing.T) {
	for input, want := range map[string]string{
		"test":     "test",
		"":         "",
		"a-b":      "ab",
		"yeah so":  "yeahso",
		"dot.":     "dot.",
		"Capital":  "Capital",
		"t_est":    "t_est",
		"hörnchen": "hrnchen",
	} {
		qt.Assert(t, qt.Equals(SanitizeName(input, -1), want), qt.Commentf("input: %s", input))
	}
}

func TestHaveBatchAPI(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBatchAPI)
}

func TestHaveObjName(t *testing.T) {
	testutils.CheckFeatureTest(t, haveObjName)
}

func TestObjNameAllowsDot(t *testing.T) {
	testutils.CheckFeatureTest(t, objNameAllowsDot)
}

func TestHaveNestedMaps(t *testing.T) {
	testutils.CheckFeatureTest(t, haveNestedMaps)
}

func TestHaveMapMutabilityModifiers(t *testing.T) {
	testutils.CheckFeatureTest(t, haveMapMutabilityModifiers)
}

func TestHaveMmapableMaps(t *testing.T) {
	testutils.CheckFeatureTest(t, haveMmapableMaps)
}

func TestHaveInnerMaps(t *testing.T) {
	testutils.CheckFeatureTest(t, haveInnerMaps)
}

func TestHaveProbeReadKernel(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProbeReadKernel)
}

func TestHaveBPFToBPFCalls(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFToBPFCalls)
}

func TestHaveSyscallWrapper(t *testing.T) {
	testutils.CheckFeatureTest(t, haveSyscallWrapper)
}

func TestHaveProgramExtInfos(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgramExtInfos)
}
