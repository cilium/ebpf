package btf

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestLoadKernelSpec(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/vmlinux not present")
	}

	_, err := LoadKernelSpec()
	if err != nil {
		t.Fatal("Can't load kernel spec:", err)
	}
}

func TestLoadKernelModuleSpec(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/btf_testmod"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/btf_testmod not present")
	}

	_, err := LoadKernelModuleSpec("btf_testmod")
	qt.Assert(t, qt.IsNil(err))
}
