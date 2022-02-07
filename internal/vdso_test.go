package internal

import (
	"errors"
	"os"
	"testing"
)

func TestAuxvVDSOMemoryAddress(t *testing.T) {
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

func TestAuxvNoVDSO(t *testing.T) {
	// Copy of auxv.bin with the vDSO pointer removed.
	av, err := os.Open("../testdata/auxv_no_vdso.bin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { av.Close() })

	_, err = vdsoMemoryAddress(av)
	if want, got := errAuxvNoVDSO, err; !errors.Is(got, want) {
		t.Fatalf("expected error '%v', got: %v", want, got)
	}
}

func TestLinuxVersionCodeEmbedded(t *testing.T) {
	tests := []struct {
		file    string
		version uint32
	}{
		{
			"../testdata/vdso.bin",
			uint32(328828), // 5.4.124
		},
		{
			"../testdata/vdso_multiple_notes.bin",
			uint32(328875), // Container Optimized OS v85 with a 5.4.x kernel
		},
	}

	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			vdso, err := os.Open(test.file)
			if err != nil {
				t.Fatal(err)
			}
			defer vdso.Close()

			vc, err := vdsoLinuxVersionCode(vdso)
			if err != nil {
				t.Fatal(err)
			}

			if vc != test.version {
				t.Errorf("Expected version code %d, got %d", test.version, vc)
			}
		})
	}
}
