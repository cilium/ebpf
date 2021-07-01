package ebpf

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
	"golang.org/x/sys/unix"
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

func TestWrapObjError(t *testing.T) {
	for inErr, outErr := range map[error]error{
		unix.ENOENT: ErrNotExist,
		unix.EPERM:  unix.EPERM,
		unix.EACCES: unix.EACCES,
		unix.ENOANO: unix.ENOANO, // dummy error -- never actually returned
	} {
		gotErr := wrapObjError(inErr)
		if !errors.Is(gotErr, outErr) {
			t.Errorf("wrapObjError(%v) doesn't wrap %v: got %v", inErr, outErr, gotErr)
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
