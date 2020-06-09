package ebpf

import (
	"flag"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestLoadCollectionSpec(t *testing.T) {
	testutils.TestFiles(t, "testdata/loader-*.elf", func(t *testing.T, file string) {
		spec, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatal("Can't parse ELF:", err)
		}

		hashMapSpec := &MapSpec{
			Name:       "hash_map",
			Type:       Hash,
			KeySize:    4,
			ValueSize:  2,
			MaxEntries: 1,
		}
		checkMapSpec(t, spec.Maps, "hash_map", hashMapSpec)
		checkMapSpec(t, spec.Maps, "array_of_hash_map", &MapSpec{
			Name:       "hash_map",
			Type:       ArrayOfMaps,
			KeySize:    4,
			MaxEntries: 2,
		})
		spec.Maps["array_of_hash_map"].InnerMap = spec.Maps["hash_map"]

		hashMap2Spec := &MapSpec{
			Name:       "",
			Type:       Hash,
			KeySize:    4,
			ValueSize:  1,
			MaxEntries: 2,
			Flags:      1,
		}
		checkMapSpec(t, spec.Maps, "hash_map2", hashMap2Spec)
		checkMapSpec(t, spec.Maps, "hash_of_hash_map", &MapSpec{
			Type:       HashOfMaps,
			KeySize:    4,
			MaxEntries: 2,
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

		if rodata := spec.Maps[".rodata"]; rodata != nil {
			err := spec.RewriteConstants(map[string]interface{}{
				"arg": uint32(1),
			})
			if err != nil {
				t.Fatal("Can't rewrite constant:", err)
			}

			err = spec.RewriteConstants(map[string]interface{}{
				"totallyBogus": uint32(1),
			})
			if err == nil {
				t.Error("Rewriting a bogus constant doesn't fail")
			}
		}

		t.Log(spec.Programs["xdp_prog"].Instructions)

		if spec.Programs["xdp_prog"].ByteOrder != internal.NativeEndian {
			return
		}

		coll, err := NewCollectionWithOptions(spec, CollectionOptions{
			Programs: ProgramOptions{
				LogLevel: 1,
			},
		})
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal(err)
		}
		defer coll.Close()

		ret, _, err := coll.Programs["xdp_prog"].Test(make([]byte, 14))
		if err != nil {
			t.Fatal("Can't run program:", err)
		}

		if ret != 5 {
			t.Error("Expected return value to be 5, got", ret)
		}
	})
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

	if have.ByteOrder == nil {
		t.Errorf("%s: nil ByteOrder", name)
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

func TestCollectionSpecDetach(t *testing.T) {
	coll := Collection{
		Maps: map[string]*Map{
			"foo": new(Map),
		},
		Programs: map[string]*Program{
			"bar": new(Program),
		},
	}

	foo := coll.DetachMap("foo")
	if foo == nil {
		t.Error("Program not returned from DetachMap")
	}

	if _, ok := coll.Programs["foo"]; ok {
		t.Error("DetachMap doesn't remove map from Maps")
	}

	bar := coll.DetachProgram("bar")
	if bar == nil {
		t.Fatal("Program not returned from DetachProgram")
	}

	if _, ok := coll.Programs["bar"]; ok {
		t.Error("DetachProgram doesn't remove program from Programs")
	}
}

func TestLoadInvalidMap(t *testing.T) {
	testutils.TestFiles(t, "testdata/invalid_map-*.elf", func(t *testing.T, file string) {
		_, err := LoadCollectionSpec(file)
		t.Log(err)
		if err == nil {
			t.Fatal("Loading an invalid map should fail")
		}
	})
}

var (
	elfPath    = flag.String("elfs", "", "`Path` containing libbpf-compatible ELFs")
	elfPattern = flag.String("elf-pattern", "test_*.o", "Glob `pattern` for object files that should be tested")
)

func TestLibBPFCompat(t *testing.T) {
	if *elfPath == "" {
		// Specify the path to the directory containing the eBPF for
		// the kernel's selftests if you want to run this test.
		// As of 5.2 that is tools/testing/selftests/bpf/
		t.Skip("No path specified")
	}

	testutils.TestFiles(t, filepath.Join(*elfPath, *elfPattern), func(t *testing.T, file string) {
		if strings.Contains(filepath.Base(file), "_core_") {
			t.Skip("CO-RE is not implemented")
		}

		t.Parallel()

		spec, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatalf("Can't read %s: %s", file, err)
		}

		coll, err := NewCollection(spec)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal(err)
		}
		coll.Close()
	})
}

func TestGetProgType(t *testing.T) {
	testcases := []struct {
		section string
		pt      ProgramType
		at      AttachType
		to      string
	}{
		{"socket/garbage", SocketFilter, AttachNone, ""},
		{"kprobe/func", Kprobe, AttachNone, "func"},
		{"xdp/foo", XDP, AttachNone, ""},
		{"cgroup_skb/ingress", CGroupSKB, AttachCGroupInetIngress, ""},
		{"iter/bpf_map", Tracing, AttachTraceIter, "bpf_map"},
	}

	for _, tc := range testcases {
		pt, at, to := getProgType(tc.section)
		if pt != tc.pt {
			t.Errorf("section %s: expected type %s, got %s", tc.section, tc.pt, pt)
		}

		if at != tc.at {
			t.Errorf("section %s: expected attach type %s, got %s", tc.section, tc.at, at)
		}

		if to != tc.to {
			t.Errorf("section %s: expected attachment to be %q, got %q", tc.section, tc.to, to)
		}
	}
}
