package internal

import (
	"os"
	"testing"
)

func TestVDSOMemoryAddress(t *testing.T) {
	av, err := os.Open("../testdata/auxv.bin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { av.Close() })

	addr, err := vdsoMemoryAddress(av)
	if err != nil {
		t.Fatal(err)
	}

	expected := uint64(0x7ffd377e5000)
	if addr != expected {
		t.Errorf("Expected vDSO memory address %x, got %x", expected, addr)
	}
}

func TestLinuxVersionCodeEmbedded(t *testing.T) {
	vdso, err := os.Open("../testdata/vdso.bin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vdso.Close() })

	vc, err := linuxVersionCode(vdso)
	if err != nil {
		t.Fatal(err)
	}

	expected := uint32(328828) // 5.4.124
	if vc != expected {
		t.Errorf("Expected version code %d, got %d", expected, vc)
	}
}
