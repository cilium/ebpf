package ebpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestObjNameCharacters(t *testing.T) {
	for in, valid := range map[string]bool{
		"test":    true,
		"":        true,
		"a-b":     false,
		"yeah so": false,
		"dot.":    objNameAllowsDot() == nil,
		"Capital": true,
	} {
		result := strings.IndexFunc(in, invalidBPFObjNameChar) == -1
		if result != valid {
			t.Errorf("Name '%s' classified incorrectly", in)
		}
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
