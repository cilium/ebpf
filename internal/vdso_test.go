package internal

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestAuxvVDSOMemoryAddress(t *testing.T) {
	for _, testcase := range []struct {
		source  string
		is32bit bool
		address uint64
	}{
		{"auxv64le.bin", false, 0x7ffd377e5000},
		{"auxv32le.bin", true, 0xb7fc3000},
	} {
		t.Run(testcase.source, func(t *testing.T) {
			av, err := newAuxFileReader("testdata/"+testcase.source, binary.LittleEndian, testcase.is32bit)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { av.Close() })

			addr, err := vdsoMemoryAddress(av)
			if err != nil {
				t.Fatal(err)
			}

			if uint64(addr) != testcase.address {
				t.Errorf("Expected vDSO memory address %x, got %x", testcase.address, addr)
			}
		})
	}
}

func TestAuxvNoVDSO(t *testing.T) {
	// Copy of auxv.bin with the vDSO pointer removed.
	av, err := newAuxFileReader("testdata/auxv64le_no_vdso.bin", binary.LittleEndian, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { av.Close() })

	_, err = vdsoMemoryAddress(av)
	if want, got := errAuxvNoVDSO, err; !errors.Is(got, want) {
		t.Fatalf("expected error '%v', got: %v", want, got)
	}
}

func TestVDSOVersion(t *testing.T) {
	_, err := vdsoVersion()
	qt.Assert(t, qt.IsNil(err))
}

func TestLinuxVersionCodeEmbedded(t *testing.T) {
	tests := []struct {
		file    string
		version uint32
	}{
		{
			"testdata/vdso.bin",
			uint32(328828), // 5.4.124
		},
		{
			"testdata/vdso_multiple_notes.bin",
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
