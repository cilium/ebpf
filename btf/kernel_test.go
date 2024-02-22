package btf

import (
	"os"
	"testing"
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
