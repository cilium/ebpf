package ebpf

import (
	"flag"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadCollectionSpec(t *testing.T) {
	files, err := filepath.Glob("testdata/loader-*.elf")
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			spec, err := LoadCollectionSpec(file)
			if err != nil {
				t.Fatal("Can't parse ELF:", err)
			}

			hashMapSpec := &MapSpec{
				"hash_map",
				Hash,
				4,
				2,
				1,
				0,
				nil,
			}
			checkMapSpec(t, spec.Maps, "hash_map", hashMapSpec)
			checkMapSpec(t, spec.Maps, "array_of_hash_map", &MapSpec{
				"hash_map", ArrayOfMaps, 4, 0, 2, 0, nil,
			})
			spec.Maps["array_of_hash_map"].InnerMap = spec.Maps["hash_map"]

			hashMap2Spec := &MapSpec{
				"",
				Hash,
				4,
				1,
				2,
				1,
				nil,
			}
			checkMapSpec(t, spec.Maps, "hash_map2", hashMap2Spec)
			checkMapSpec(t, spec.Maps, "hash_of_hash_map", &MapSpec{
				"", HashOfMaps, 4, 0, 2, 0, nil,
			})
			spec.Maps["hash_of_hash_map"].InnerMap = spec.Maps["hash_map2"]

			checkProgramSpec(t, spec.Programs, "xdp_prog", &ProgramSpec{
				Type:          XDP,
				License:       "MIT",
				KernelVersion: 0,
			})
			checkProgramSpec(t, spec.Programs, "no_relocation", &ProgramSpec{
				Type:          SocketFilter,
				License:       "MIT",
				KernelVersion: 0,
			})

			t.Log(spec.Programs["xdp_prog"].Instructions)

			coll, err := NewCollection(spec)
			if err != nil {
				t.Fatal(err)
			}
			defer coll.Close()

			hash := coll.DetachMap("hash_map")
			if hash == nil {
				t.Fatal("Program not returned from DetachMap")
			}
			defer hash.Close()

			if _, ok := coll.Programs["hash_map"]; ok {
				t.Error("DetachMap doesn't remove map from Maps")
			}

			prog := coll.DetachProgram("xdp_prog")
			if prog == nil {
				t.Fatal("Program not returned from DetachProgram")
			}
			defer prog.Close()

			if _, ok := coll.Programs["xdp_prog"]; ok {
				t.Error("DetachProgram doesn't remove program from Programs")
			}
		})
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
		t.Fatalf("Missing program %s", name)
		return
	}

	if have.License != want.License {
		t.Errorf("%s: expected %v license, got %v", name, want.License, have.License)
	}

	if have.Type != want.Type {
		t.Errorf("%s: expected %v program, got %v", name, want.Type, have.Type)
	}

	if want.Instructions != nil && !reflect.DeepEqual(have.Instructions, want.Instructions) {
		t.Log("Expected program")
		t.Log(want.Instructions)
		t.Log("Actual program")
		t.Log(want.Instructions)
		t.Error("Instructions do not match")
	}
}

func TestLoadInvalidMap(t *testing.T) {
	_, err := LoadCollectionSpec("testdata/invalid_map.elf")
	t.Log(err)
	if err == nil {
		t.Fatal("should be fail")
	}
}

var elfPattern = flag.String("elfs", "", "`PATTERN` for a path containing libbpf-compatible ELFs")

func TestLibBPFCompat(t *testing.T) {
	if *elfPattern == "" {
		// Specify the path to the directory containing the eBPF for
		// the kernel's selftests.
		// As of 5.2 that is tools/testing/selftests/bpf/.
		t.Skip("No path specified")
	}

	files, err := filepath.Glob(*elfPattern)
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range files {
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			spec, err := LoadCollectionSpec(file)
			if err != nil {
				t.Fatalf("Can't read %s: %s", name, err)
			}

			coll, err := NewCollection(spec)
			if err != nil {
				t.Fatal(err)
			}
			coll.Close()
		})
	}
}
