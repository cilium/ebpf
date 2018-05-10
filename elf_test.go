package ebpf

import (
	"os"
	"testing"
)

func TestNewCollectionSpecFromELF(t *testing.T) {
	fh, err := os.Open("testdata/test.elf")
	if err != nil {
		t.Fatal("Can't open test ELF:", err)
	}
	defer fh.Close()

	spec, err := NewCollectionSpecFromELF(fh)
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}

	hashMapSpec := &MapSpec{Hash, 4, 2, 42, 4242, nil}
	checkMapSpec(t, spec.Maps, "hash_map", hashMapSpec)
	checkMapSpec(t, spec.Maps, "array_of_hash_map", &MapSpec{
		ArrayOfMaps, 4, 0, 2, 0, hashMapSpec,
	})

	hashMap2Spec := &MapSpec{Hash, 2, 1, 21, 2121, nil}
	checkMapSpec(t, spec.Maps, "hash_map2", hashMap2Spec)
	checkMapSpec(t, spec.Maps, "hash_of_hash_map", &MapSpec{
		HashOfMaps, 4, 0, 2, 0, hashMap2Spec,
	})

	checkProgramSpec(t, spec.Programs, "xdp_prog", &ProgramSpec{
		Type:    XDP,
		License: "MIT",
		Refs: map[string][]*BPFInstruction{
			"hash_map":    nil,
			"hash_map2":   nil,
			"non_map":     nil,
			"helper_func": nil,
		},
	})
	checkProgramSpec(t, spec.Programs, "no_relocation", &ProgramSpec{
		Type:    SocketFilter,
		License: "MIT",
	})

	if _, ok := spec.Programs["xdp_prog"].Refs["non_map"]; !ok {
		t.Error("Missing references for 'non_map'")
	}
}

func checkMapSpec(t *testing.T, maps map[string]*MapSpec, name string, want *MapSpec) {
	t.Helper()

	have, ok := maps[name]
	if !ok {
		t.Errorf("Missing map %s", name)
		return
	}

	mapSpecEqual(t, name, have, want)
}

func mapSpecEqual(t *testing.T, name string, have, want *MapSpec) {
	t.Helper()

	if have.Type != want.Type {
		t.Errorf("%s: expected type %v, got %v", name, want.Type, have.Type)
	}

	if have.KeySize != want.KeySize {
		t.Errorf("%s: expected key size %v, got %v", name, want.KeySize, have.KeySize)
	}

	if have.ValueSize != want.ValueSize {
		t.Errorf("%s: expected value size %v, got %v", name, want.ValueSize, have.ValueSize)
	}

	if have.MaxEntries != want.MaxEntries {
		t.Errorf("%s: expected max entries %v, got %v", name, want.MaxEntries, have.MaxEntries)
	}

	if have.Flags != want.Flags {
		t.Errorf("%s: expected flags %v, got %v", name, want.Flags, have.Flags)
	}

	switch {
	case have.InnerMap != nil && want.InnerMap == nil:
		t.Errorf("%s: extraneous InnerMap", name)
	case have.InnerMap == nil && want.InnerMap != nil:
		t.Errorf("%s: missing InnerMap", name)
	case have.InnerMap != nil && want.InnerMap != nil:
		mapSpecEqual(t, name+".InnerMap", have.InnerMap, want.InnerMap)
	}
}

func checkProgramSpec(t *testing.T, progs map[string]*ProgramSpec, name string, want *ProgramSpec) {
	t.Helper()

	have, ok := progs[name]
	if !ok {
		t.Errorf("Missing program %s", name)
		return
	}

	if have.License != want.License {
		t.Errorf("%s: expected %v license, got %v", name, want.License, have.License)
	}

	if have.Type != want.Type {
		t.Errorf("%s: expected %v program, got %v", name, want.Type, have.Type)
	}

	for sym, wantOps := range want.Refs {
		if wantOps != nil {
			// It's currently not possbile to compare instructions due to
			// the presence of the extra field.
			t.Fatalf("Checking instructions is not supported")
		}

		if _, ok := have.Refs[sym]; !ok {
			t.Errorf("Missing reference for %v", sym)
			continue
		}
	}

	for sym := range have.Refs {
		if _, ok := want.Refs[sym]; !ok {
			t.Errorf("extranenous symbol %v", sym)
		}
	}
}
