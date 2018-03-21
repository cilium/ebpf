package ebpf

import (
	"os"
	"testing"
)

func TestGetSpecsFromELF(t *testing.T) {
	fh, err := os.Open("testdata/test.elf")
	if err != nil {
		t.Fatal("Can't open test ELF:", err)
	}
	defer fh.Close()

	progs, maps, err := GetSpecsFromELF(fh)
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}

	checkMapSpec(t, maps, "hash_map", Hash, 4, 2, 42, 4242)

	checkProgramSpec(t, progs, "xdp_prog", XDP)
}

func checkMapSpec(t *testing.T, maps map[string]MapSpec, name string, typ MapType, keySize, valueSize, maxEntries, flags uint32) {
	t.Helper()

	spec, ok := maps[name]
	if !ok {
		t.Errorf("Missing map %s", name)
		return
	}

	if spec.MapType() != typ {
		t.Errorf("%s: expected type %v, got %v", name, typ, spec.MapType())
	}

	if spec.KeySize() != keySize {
		t.Errorf("%s: expected key size %v, got %v", name, keySize, spec.KeySize())
	}

	if spec.ValueSize() != valueSize {
		t.Errorf("%s: expected value size %v, got %v", name, valueSize, spec.ValueSize())
	}

	if spec.MaxEntries() != maxEntries {
		t.Errorf("%s: expected max entries %v, got %v", name, maxEntries, spec.MaxEntries())
	}

	if spec.Flags() != flags {
		t.Errorf("%s: expected flags %v, got %v", name, flags, spec.Flags())
	}
}

func checkProgramSpec(t *testing.T, progs map[string]ProgramSpec, name string, typ ProgType) {
	t.Helper()

	spec, ok := progs[name]
	if !ok {
		t.Errorf("Missing program %s", name)
		return
	}

	if spec.License() != "MIT" {
		t.Errorf("%s: expected MIT license, got %v", name, spec.License())
	}

	if spec.ProgType() != typ {
		t.Errorf("%s: expected %v program, got %v", name, typ, spec.ProgType())
	}
}
