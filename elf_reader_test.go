package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/go-quicktest/qt"
)

func TestLoadCollectionSpec(t *testing.T) {
	coll := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"hash_map": {
				Name:       "hash_map",
				Type:       Hash,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: 1,
				Flags:      unix.BPF_F_NO_PREALLOC,
			},
			"hash_map2": {
				Name:       "hash_map2",
				Type:       Hash,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: 2,
			},
			"array_of_hash_map": {
				Name:       "array_of_hash_map",
				Type:       ArrayOfMaps,
				KeySize:    4,
				MaxEntries: 2,
			},
			"perf_event_array": {
				Name:       "perf_event_array",
				Type:       PerfEventArray,
				MaxEntries: 4096,
			},
			"btf_pin": {
				Name:       "btf_pin",
				Type:       Hash,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: 1,
				Pinning:    PinByName,
			},
			"btf_outer_map": {
				Name:       "btf_outer_map",
				Type:       ArrayOfMaps,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
				InnerMap: &MapSpec{
					Name:       "btf_outer_map_inner",
					Type:       Hash,
					KeySize:    4,
					ValueSize:  4,
					MaxEntries: 1,
				},
			},
			"btf_outer_map_anon": {
				Name:       "btf_outer_map_anon",
				Type:       ArrayOfMaps,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
				InnerMap: &MapSpec{
					Name:       "btf_outer_map_anon_inner",
					Type:       Hash,
					KeySize:    4,
					ValueSize:  4,
					MaxEntries: 1,
				},
			},
			"btf_typedef_map": {
				Name:       "btf_typedef_map",
				Type:       Array,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ProgramSpec{
			"xdp_prog": {
				Name:        "xdp_prog",
				Type:        XDP,
				SectionName: "xdp",
				License:     "MIT",
			},
			"no_relocation": {
				Name:        "no_relocation",
				Type:        SocketFilter,
				SectionName: "socket",
				License:     "MIT",
			},
			"asm_relocation": {
				Name:        "asm_relocation",
				Type:        SocketFilter,
				SectionName: "socket/2",
				License:     "MIT",
			},
			"data_sections": {
				Name:        "data_sections",
				Type:        SocketFilter,
				SectionName: "socket/3",
				License:     "MIT",
			},
			"global_fn3": {
				Name:        "global_fn3",
				Type:        UnspecifiedProgram,
				SectionName: "other",
				License:     "MIT",
			},
			"static_fn": {
				Name:        "static_fn",
				Type:        UnspecifiedProgram,
				SectionName: "static",
				License:     "MIT",
			},
			"anon_const": {
				Name:        "anon_const",
				Type:        SocketFilter,
				SectionName: "socket/4",
				License:     "MIT",
			},
		},
	}

	cmpOpts := cmp.Options{
		// Dummy Comparer that works with empty readers to support test cases.
		cmp.Comparer(func(a, b bytes.Reader) bool {
			if a.Len() == 0 && b.Len() == 0 {
				return true
			}
			return false
		}),
		cmpopts.IgnoreTypes(new(btf.Spec)),
		cmpopts.IgnoreFields(CollectionSpec{}, "ByteOrder", "Types"),
		cmpopts.IgnoreFields(ProgramSpec{}, "Instructions", "ByteOrder"),
		cmpopts.IgnoreFields(MapSpec{}, "Key", "Value"),
		cmpopts.IgnoreUnexported(ProgramSpec{}),
		cmpopts.IgnoreMapEntries(func(key string, _ *MapSpec) bool {
			if key == ".bss" || key == ".data" || strings.HasPrefix(key, ".rodata") {
				return true
			}
			return false
		}),
	}

	testutils.Files(t, testutils.Glob(t, "testdata/loader-*.elf"), func(t *testing.T, file string) {
		have, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatal("Can't parse ELF:", err)
		}

		err = have.RewriteConstants(map[string]interface{}{
			"arg":  uint32(1),
			"arg2": uint32(2),
		})
		if err != nil {
			t.Fatal("Can't rewrite constant:", err)
		}

		err = have.RewriteConstants(map[string]interface{}{
			"totallyBogus": uint32(1),
		})
		if err == nil {
			t.Error("Rewriting a bogus constant doesn't fail")
		}

		if diff := cmp.Diff(coll, have, cmpOpts...); diff != "" {
			t.Errorf("MapSpec mismatch (-want +got):\n%s", diff)
		}

		if have.ByteOrder != internal.NativeEndian {
			return
		}

		have.Maps["array_of_hash_map"].InnerMap = have.Maps["hash_map"]
		coll, err := NewCollectionWithOptions(have, CollectionOptions{
			Maps: MapOptions{
				PinPath: testutils.TempBPFFS(t),
			},
			Programs: ProgramOptions{
				LogLevel: LogLevelBranch,
			},
		})

		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal(err)
		}
		defer coll.Close()

		ret, _, err := coll.Programs["xdp_prog"].Test(internal.EmptyBPFContext)
		if err != nil {
			t.Fatal("Can't run program:", err)
		}

		if ret != 7 {
			t.Error("Unexpected return value:", ret)
		}
	})
}

func BenchmarkELFLoader(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = LoadCollectionSpec("testdata/loader-el.elf")
	}
}

func TestDataSections(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/loader-%s.elf")
	coll, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(coll.Programs["data_sections"].Instructions)

	var obj struct {
		Program *Program `ebpf:"data_sections"`
	}

	err = coll.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Program.Close()

	ret, _, err := obj.Program.Test(internal.EmptyBPFContext)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Error("BPF assertion failed on line", ret)
	}
}

func TestInlineASMConstant(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/loader-%s.elf")
	coll, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	spec := coll.Programs["asm_relocation"]
	if spec.Instructions[0].Reference() != "MY_CONST" {
		t.Fatal("First instruction is not a reference to MY_CONST")
	}

	// -1 is used by the loader to find unrewritten maps.
	spec.Instructions[0].Constant = -1

	t.Log(spec.Instructions)

	var obj struct {
		Program *Program `ebpf:"asm_relocation"`
	}

	err = coll.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	obj.Program.Close()
}

func TestFreezeRodata(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "sk_lookup program type")

	file := testutils.NativeFile(t, "testdata/constants-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Program *Program `ebpf:"freeze_rodata"`
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"ret": uint32(1),
	}); err != nil {
		t.Fatal(err)
	}

	err = spec.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Program.Close()
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
	file := testutils.NativeFile(t, "testdata/invalid_map-%s.elf")
	cs, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal("Can't load CollectionSpec", err)
	}

	ms, ok := cs.Maps["invalid_map"]
	if !ok {
		t.Fatal("invalid_map not found in CollectionSpec")
	}

	m, err := NewMap(ms)
	t.Log(err)
	if err == nil {
		m.Close()
		t.Fatal("Creating a Map from a MapSpec with non-zero Extra is expected to fail.")
	}
}

func TestLoadInvalidMapMissingSymbol(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/invalid_map_static-%s.elf")
	_, err := LoadCollectionSpec(file)
	t.Log(err)
	if err == nil {
		t.Fatal("Loading a map with static qualifier should fail")
	}
}

func TestLoadInitializedBTFMap(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/btf_map_init-*.elf"), func(t *testing.T, file string) {
		coll, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatal(err)
		}

		t.Run("NewCollection", func(t *testing.T) {
			if coll.ByteOrder != internal.NativeEndian {
				t.Skipf("Skipping %s collection", coll.ByteOrder)
			}

			tmp, err := NewCollection(coll)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal("NewCollection failed:", err)
			}
			tmp.Close()
		})

		t.Run("prog_array", func(t *testing.T) {
			m, ok := coll.Maps["prog_array_init"]
			if !ok {
				t.Fatal("map prog_array_init not found in program")
			}

			if len(m.Contents) != 1 {
				t.Error("expecting exactly 1 item in MapSpec contents")
			}

			p := m.Contents[0]
			if cmp.Equal(p.Key, 1) {
				t.Errorf("expecting MapSpec entry Key to equal 1, got %v", p.Key)
			}

			if _, ok := p.Value.(string); !ok {
				t.Errorf("expecting MapSpec entry Value to be a string, got %T", p.Value)
			}

			if p.Value != "tail_1" {
				t.Errorf("expected MapSpec entry Value 'tail_1', got: %s", p.Value)
			}
		})

		t.Run("array_of_maps", func(t *testing.T) {
			m, ok := coll.Maps["outer_map_init"]
			if !ok {
				t.Fatal("map outer_map_init not found in program")
			}

			if len(m.Contents) != 1 {
				t.Error("expecting exactly 1 item in MapSpec contents")
			}

			if m.Key == nil {
				t.Error("Expected non-nil key")
			}

			if m.Value == nil {
				t.Error("Expected non-nil value")
			}

			if m.InnerMap.Key == nil {
				t.Error("Expected non-nil InnerMap key")
			}

			if m.InnerMap.Value == nil {
				t.Error("Expected non-nil InnerMap value")
			}

			p := m.Contents[0]
			if cmp.Equal(p.Key, 1) {
				t.Errorf("expecting MapSpec entry Key to equal 1, got %v", p.Key)
			}

			if _, ok := p.Value.(string); !ok {
				t.Errorf("expecting MapSpec entry Value to be a string, got %T", p.Value)
			}

			if p.Value != "inner_map" {
				t.Errorf("expected MapSpec entry Value 'inner_map', got: %s", p.Value)
			}
		})
	})
}

func TestLoadInvalidInitializedBTFMap(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/invalid_btf_map_init-%s.elf")
	_, err := LoadCollectionSpec(file)
	t.Log(err)
	if !errors.Is(err, internal.ErrNotSupported) {
		t.Fatal("Loading an initialized BTF map should be unsupported")
	}
}

func TestStringSection(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/strings-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatalf("load collection spec: %s", err)
	}

	for name := range spec.Maps {
		t.Log(name)
	}

	strMap := spec.Maps[".rodata.str1.1"]
	if strMap == nil {
		t.Fatal("Unable to find map '.rodata.str1.1' in loaded collection")
	}

	if !strMap.Freeze {
		t.Fatal("Read only data maps should be frozen")
	}

	if strMap.Flags != unix.BPF_F_RDONLY_PROG {
		t.Fatal("Read only data maps should have the prog-read-only flag set")
	}

	coll, err := NewCollection(spec)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatalf("new collection: %s", err)
	}
	defer coll.Close()

	prog := coll.Programs["filter"]
	if prog == nil {
		t.Fatal("program not found")
	}

	testMap := coll.Maps["my_map"]
	if testMap == nil {
		t.Fatal("test map not found")
	}

	_, err = prog.Run(&RunOptions{
		Data: internal.EmptyBPFContext, // Min size for XDP programs
	})
	if err != nil {
		t.Fatalf("prog run: %s", err)
	}

	key := []byte("This string is allocated in the string section\n\x00")
	var value uint32
	if err = testMap.Lookup(&key, &value); err != nil {
		t.Fatalf("test map lookup: %s", err)
	}

	if value != 1 {
		t.Fatal("Test map value not 1!")
	}
}

func TestLoadRawTracepoint(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.17", "BPF_RAW_TRACEPOINT API")

	file := testutils.NativeFile(t, "testdata/raw_tracepoint-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}

	coll, err := NewCollectionWithOptions(spec, CollectionOptions{
		Programs: ProgramOptions{
			LogLevel: LogLevelBranch,
		},
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create collection:", err)
	}

	coll.Close()
}

func TestTailCall(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/btf_map_init-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		TailMain  *Program `ebpf:"tail_main"`
		ProgArray *Map     `ebpf:"prog_array_init"`
	}

	err = spec.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.TailMain.Close()
	defer obj.ProgArray.Close()

	ret, _, err := obj.TailMain.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	// Expect the tail_1 tail call to be taken, returning value 42.
	if ret != 42 {
		t.Fatalf("Expected tail call to return value 42, got %d", ret)
	}
}

func TestKconfigKernelVersion(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/kconfig-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Main *Program `ebpf:"kernel_version"`
	}

	testutils.SkipOnOldKernel(t, "5.2", "readonly maps")

	err = spec.LoadAndAssign(&obj, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Main.Close()

	ret, _, err := obj.Main.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	v, err := internal.KernelVersion()
	if err != nil {
		t.Fatalf("getting kernel version: %s", err)
	}

	version := v.Kernel()
	if ret != version {
		t.Fatalf("Expected eBPF to return value %d, got %d", version, ret)
	}
}

func TestKconfigSyscallWrapper(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/kconfig-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Main *Program `ebpf:"syscall_wrapper"`
	}

	err = spec.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Main.Close()

	ret, _, err := obj.Main.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	var expected uint32
	if testutils.IsKernelLessThan(t, "4.17") {
		expected = 0
	} else {
		expected = 1
	}

	if ret != expected {
		t.Fatalf("Expected eBPF to return value %d, got %d", expected, ret)
	}
}

func TestKconfigConfig(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/kconfig_config-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Main     *Program `ebpf:"kconfig"`
		ArrayMap *Map     `ebpf:"array_map"`
	}

	err = spec.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Main.Close()
	defer obj.ArrayMap.Close()

	_, _, err = obj.Main.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	var value uint64
	err = obj.ArrayMap.Lookup(uint32(0), &value)
	if err != nil {
		t.Fatal(err)
	}

	// CONFIG_HZ must have a value.
	qt.Assert(t, qt.Not(qt.Equals(value, 0)))
}

func TestKfunc(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.18", "kfunc support")
	file := testutils.NativeFile(t, "testdata/kfunc-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Main *Program `ebpf:"call_kfunc"`
	}

	err = spec.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer obj.Main.Close()

	ret, _, err := obj.Main.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 1 {
		t.Fatalf("Expected kfunc to return value 1, got %d", ret)
	}
}

func TestWeakKfunc(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.18", "kfunc support")
	file := testutils.NativeFile(t, "testdata/kfunc-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Missing *Program `ebpf:"weak_kfunc_missing"`
		Calling *Program `ebpf:"call_weak_kfunc"`
	}

	err = spec.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer obj.Missing.Close()
	defer obj.Calling.Close()
}

func TestInvalidKfunc(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.18", "kfunc support")

	if !haveTestmod(t) {
		t.Skip("bpf_testmod not loaded")
	}

	file := testutils.NativeFile(t, "testdata/invalid-kfunc-%s.elf")
	coll, err := LoadCollection(file)
	if err == nil {
		coll.Close()
		t.Fatal("Expected an error")
	}

	var ike *incompatibleKfuncError
	if !errors.As(err, &ike) {
		t.Fatalf("Expected an error wrapping incompatibleKfuncError, got %s", err)
	}
}

func TestKfuncKmod(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.18", "Kernel module function calls")

	if !haveTestmod(t) {
		t.Skip("bpf_testmod not loaded")
	}

	file := testutils.NativeFile(t, "testdata/kfunc-kmod-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Main *Program `ebpf:"call_kfunc"`
	}

	err = spec.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatalf("%v+", err)
	}
	defer obj.Main.Close()

	ret, _, err := obj.Main.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 1 {
		t.Fatalf("Expected kfunc to return value 1, got %d", ret)
	}
}

func TestSubprogRelocation(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.13", "bpf_for_each_map_elem")

	file := testutils.NativeFile(t, "testdata/subprog_reloc-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Main    *Program `ebpf:"fp_relocation"`
		HashMap *Map     `ebpf:"hash_map"`
	}

	err = spec.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Main.Close()
	defer obj.HashMap.Close()

	ret, _, err := obj.Main.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 42 {
		t.Fatalf("Expected subprog reloc to return value 42, got %d", ret)
	}
}

func TestUnassignedProgArray(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/btf_map_init-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	// tail_main references a ProgArray that is not being assigned
	// to this struct. Normally, this would clear all its entries
	// and make any tail calls into the ProgArray result in a miss.
	// The library needs to explicitly refuse such operations.
	var obj struct {
		TailMain *Program `ebpf:"tail_main"`
		// ProgArray *Map     `ebpf:"prog_array_init"`
	}

	err = spec.LoadAndAssign(&obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err == nil {
		obj.TailMain.Close()
		t.Fatal("Expecting LoadAndAssign to return error")
	}
}

func TestIPRoute2Compat(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/iproute2_map_compat-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}

	ms, ok := spec.Maps["hash_map"]
	if !ok {
		t.Fatal("Map hash_map not found")
	}

	var id, pinning, innerID, innerIndex uint32

	if ms.Extra == nil {
		t.Fatal("missing extra bytes")
	}

	switch {
	case binary.Read(ms.Extra, spec.ByteOrder, &id) != nil:
		t.Fatal("missing id")
	case binary.Read(ms.Extra, spec.ByteOrder, &pinning) != nil:
		t.Fatal("missing pinning")
	case binary.Read(ms.Extra, spec.ByteOrder, &innerID) != nil:
		t.Fatal("missing inner_id")
	case binary.Read(ms.Extra, spec.ByteOrder, &innerIndex) != nil:
		t.Fatal("missing inner_idx")
	}

	if id != 0 || innerID != 0 || innerIndex != 0 {
		t.Fatal("expecting id, inner_id and inner_idx to be zero")
	}

	if pinning != 2 {
		t.Fatal("expecting pinning field to be 2 (PIN_GLOBAL_NS)")
	}

	// iproute2 (tc) pins maps in /sys/fs/bpf/tc/globals with PIN_GLOBAL_NS,
	// which needs to be configured in this library using MapOptions.PinPath.
	// For the sake of the test, we use a tempdir on bpffs below.
	ms.Pinning = PinByName

	coll, err := NewCollectionWithOptions(spec, CollectionOptions{
		Maps: MapOptions{
			PinPath: testutils.TempBPFFS(t),
		},
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create collection:", err)
	}

	coll.Close()
}

var (
	elfPath    = flag.String("elfs", os.Getenv("KERNEL_SELFTESTS"), "`Path` containing libbpf-compatible ELFs (defaults to $KERNEL_SELFTESTS)")
	elfPattern = flag.String("elf-pattern", "*.o", "Glob `pattern` for object files that should be tested")
)

func TestLibBPFCompat(t *testing.T) {
	if *elfPath == "" {
		// Specify the path to the directory containing the eBPF for
		// the kernel's selftests if you want to run this test.
		// As of 5.2 that is tools/testing/selftests/bpf/
		t.Skip("No path specified")
	}

	load := func(t *testing.T, spec *CollectionSpec, opts CollectionOptions, valid bool) {
		// Disable retrying a program load with the log enabled, it leads
		// to OOM kills.
		opts.Programs.LogDisabled = true

		coll, err := NewCollectionWithOptions(spec, opts)
		testutils.SkipIfNotSupported(t, err)
		var errno syscall.Errno
		if errors.As(err, &errno) {
			// This error is most likely from a syscall and caused by us not
			// replicating some fixups done in the selftests or the test
			// intentionally failing. This is expected, so skip the test
			// instead of failing.
			t.Skip("Skipping since the kernel rejected the program:", err)
		}
		if err == nil {
			coll.Close()
		}
		if !valid {
			if err == nil {
				t.Fatal("Expected an error during load")
			}
		} else if err != nil {
			t.Fatal("Error during loading:", err)
		}
	}

	files := testutils.Glob(t, filepath.Join(*elfPath, *elfPattern),
		// These files are only used as a source of btf.
		"btf__core_reloc_*",
	)

	testutils.Files(t, files, func(t *testing.T, path string) {
		name := selftestName(path)
		switch name {
		case "test_map_in_map", "test_select_reuseport_kern":
			t.Skip("Skipping due to missing InnerMap in map definition")
		case "test_core_autosize":
			t.Skip("Skipping since the test generates dynamic BTF")
		case "test_static_linked":
			t.Skip("Skipping since .text contains 'subprog' twice")
		case "bloom_filter_map", "bloom_filter_bench":
			t.Skip("Skipping due to missing MapExtra field in MapSpec")
		case "netif_receive_skb",
			"local_kptr_stash",
			"local_kptr_stash_fail",
			"type_cast",
			"preempted_bpf_ma_op",
			"percpu_alloc_fail":
			// Error message like
			//    fixup for CORERelocation(local_type_id, Struct:"bin_data"[0],
			//    local_id=27): invalid immediate 31, expected 27 (fixup: local_type_id=27->1)
			// See https://github.com/cilium/ebpf/issues/739
			t.Skip("Skipping due to bug in libbpf type deduplication")
		case "test_usdt", "test_urandom_usdt", "test_usdt_multispec":
			t.Skip("Skipping due to missing support for usdt.bpf.h")
		case "lsm_cgroup", "bpf_iter_ipv6_route", "test_core_extern",
			"profiler1", "profiler2", "profiler3":
			t.Skip("Skipping due to using weak CONFIG_* variables")
		case "linked_maps", "linked_maps1", "linked_maps2", "linked_funcs1", "linked_funcs2",
			"test_subskeleton", "test_subskeleton_lib":
			t.Skip("Skipping due to relying on cross ELF linking")
		case "test_log_fixup":
			t.Skip("Skipping due to intentionally broken CO-RE relocations")
		}

		t.Parallel()

		spec, err := LoadCollectionSpec(path)
		testutils.SkipIfNotSupported(t, err)
		if errors.Is(err, errUnsupportedBinding) {
			t.Skip(err)
		}
		if err != nil {
			t.Fatal(err)
		}

		switch name {
		case "test_sk_assign":
			// Test contains a legacy iproute2 bpf_elf_map definition.
			for _, m := range spec.Maps {
				if m.Extra == nil || m.Extra.Len() == 0 {
					t.Fatalf("Expected extra bytes in map %s", m.Name)
				}
				m.Extra = nil
			}

		case "fexit_bpf2bpf",
			"freplace_get_constant",
			"freplace_global_func":
			loadTargetProgram(t, spec, "test_pkt_access.bpf.o", "test_pkt_access")

		case "freplace_cls_redirect":
			loadTargetProgram(t, spec, "test_cls_redirect.bpf.o", "cls_redirect")

		case "test_trace_ext":
			loadTargetProgram(t, spec, "test_pkt_md_access.bpf.o", "test_pkt_md_access")

		case "freplace_progmap":
			loadTargetProgram(t, spec, "xdp_dummy.bpf.o", "xdp_dummy_prog")

			if prog := spec.Programs["xdp_cpumap_prog"]; prog.AttachTo == "" {
				prog.AttachTo = "xdp_dummy_prog"
			}

		case "freplace_attach_probe":
			// Looks like the test should have a target, but 6.6 selftests don't
			// seem to be using it.
		}

		var opts CollectionOptions
		for _, mapSpec := range spec.Maps {
			if mapSpec.Pinning != PinNone {
				opts.Maps.PinPath = testutils.TempBPFFS(t)
				break
			}
		}

		coreFiles := sourceOfBTF(t, path)
		if len(coreFiles) == 0 {
			// NB: test_core_reloc_kernel.o doesn't have dedicated BTF and
			// therefore goes via this code path.
			load(t, spec, opts, true)
			return
		}

		for _, coreFile := range coreFiles {
			name := selftestName(coreFile)
			t.Run(name, func(t *testing.T) {
				// Some files like btf__core_reloc_arrays___err_too_small.o
				// trigger an error on purpose. Use the name to infer whether
				// the test should succeed.
				var valid bool
				switch name {
				case "btf__core_reloc_existence___err_wrong_arr_kind",
					"btf__core_reloc_existence___err_wrong_arr_value_type",
					"btf__core_reloc_existence___err_wrong_int_kind",
					"btf__core_reloc_existence___err_wrong_int_sz",
					"btf__core_reloc_existence___err_wrong_int_type",
					"btf__core_reloc_existence___err_wrong_struct_type":
					// These tests are buggy upstream, see https://lore.kernel.org/bpf/20210420111639.155580-1-lmb@cloudflare.com/
					valid = true
				case "btf__core_reloc_ints___err_wrong_sz_16",
					"btf__core_reloc_ints___err_wrong_sz_32",
					"btf__core_reloc_ints___err_wrong_sz_64",
					"btf__core_reloc_ints___err_wrong_sz_8",
					"btf__core_reloc_arrays___err_wrong_val_type1",
					"btf__core_reloc_arrays___err_wrong_val_type2":
					// These tests are valid according to current libbpf behaviour,
					// see commit 42765ede5c54ca915de5bfeab83be97207e46f68.
					valid = true
				case "btf__core_reloc_type_id___missing_targets",
					"btf__core_reloc_flavors__err_wrong_name":
					valid = false
				case "btf__core_reloc_ints___err_bitfield":
					// Bitfields are now valid.
					valid = true
				default:
					valid = !strings.Contains(name, "___err_")
				}

				fh, err := os.Open(coreFile)
				if err != nil {
					t.Fatal(err)
				}
				defer fh.Close()

				btfSpec, err := btf.LoadSpec(coreFile)
				if err != nil {
					t.Fatal(err)
				}

				opts := opts // copy
				opts.Programs.KernelTypes = btfSpec
				load(t, spec, opts, valid)
			})
		}
	})
}

func loadTargetProgram(tb testing.TB, spec *CollectionSpec, file, program string) {
	targetSpec, err := LoadCollectionSpec(filepath.Join(*elfPath, file))
	if errors.Is(err, os.ErrNotExist) && strings.HasSuffix(file, ".bpf.o") {
		// Prior to v6.1 BPF ELF used a plain .o suffix.
		file = strings.TrimSuffix(file, ".bpf.o") + ".o"
		targetSpec, err = LoadCollectionSpec(filepath.Join(*elfPath, file))
	}
	if err != nil {
		tb.Fatalf("Can't read %s: %s", file, err)
	}

	qt.Assert(tb, qt.IsNotNil(targetSpec.Programs[program]))

	coll, err := NewCollectionWithOptions(targetSpec, CollectionOptions{
		Programs: ProgramOptions{LogDisabled: true},
	})
	if err != nil {
		tb.Fatalf("Can't load target: %s", err)
	}
	tb.Cleanup(func() { coll.Close() })

	target := coll.Programs[program]
	for _, prog := range spec.Programs {
		if prog.Type == Extension && prog.AttachType == AttachNone {
			prog.AttachTarget = target
			continue
		}

		if prog.Type == Tracing {
			switch prog.AttachType {
			case AttachTraceFEntry, AttachTraceFExit, AttachModifyReturn:
				prog.AttachTarget = target
				continue
			}
		}
	}
}

func sourceOfBTF(tb testing.TB, path string) []string {
	const testPrefix = "test_core_reloc_"
	const btfPrefix = "btf__core_reloc_"

	dir, base := filepath.Split(path)
	if !strings.HasPrefix(base, testPrefix) {
		return nil
	}

	base = strings.TrimSuffix(base[len(testPrefix):], ".o")
	switch base {
	case "bitfields_direct", "bitfields_probed":
		base = "bitfields"
	}

	return testutils.Glob(tb, filepath.Join(dir, btfPrefix+base+"*.o"))
}

func TestELFSectionProgramTypes(t *testing.T) {
	type testcase struct {
		Section     string
		ProgramType ProgramType
		AttachType  AttachType
		Flags       uint32
		Extra       string
	}

	testcases := []testcase{
		{"socket", SocketFilter, AttachNone, 0, ""},
		{"socket/garbage", SocketFilter, AttachNone, 0, ""},
		{"sk_reuseport/migrate", SkReuseport, AttachSkReuseportSelectOrMigrate, 0, ""},
		{"sk_reuseport", SkReuseport, AttachSkReuseportSelect, 0, ""},
		{"kprobe/", Kprobe, AttachNone, 0, ""},
		{"kprobe/func", Kprobe, AttachNone, 0, "func"},
		{"uprobe/", Kprobe, AttachNone, 0, ""},
		{"kretprobe/", Kprobe, AttachNone, 0, ""},
		{"uretprobe/", Kprobe, AttachNone, 0, ""},
		{"tc", SchedCLS, AttachNone, 0, ""},
		{"classifier", SchedCLS, AttachNone, 0, ""},
		{"action", SchedACT, AttachNone, 0, ""},
		{"tracepoint/", TracePoint, AttachNone, 0, ""},
		{"tp/", TracePoint, AttachNone, 0, ""},
		{"raw_tracepoint/", RawTracepoint, AttachNone, 0, ""},
		{"raw_tp/", RawTracepoint, AttachNone, 0, ""},
		{"raw_tracepoint.w/", RawTracepointWritable, AttachNone, 0, ""},
		{"raw_tp.w/", RawTracepointWritable, AttachNone, 0, ""},
		{"tp_btf/", Tracing, AttachTraceRawTp, 0, ""},
		{"fentry/", Tracing, AttachTraceFEntry, 0, ""},
		{"fmod_ret/", Tracing, AttachModifyReturn, 0, ""},
		{"fexit/", Tracing, AttachTraceFExit, 0, ""},
		{"fentry.s/", Tracing, AttachTraceFEntry, unix.BPF_F_SLEEPABLE, ""},
		{"fmod_ret.s/", Tracing, AttachModifyReturn, unix.BPF_F_SLEEPABLE, ""},
		{"fexit.s/", Tracing, AttachTraceFExit, unix.BPF_F_SLEEPABLE, ""},
		{"freplace/", Extension, AttachNone, 0, ""},
		{"lsm/foo", LSM, AttachLSMMac, 0, "foo"},
		{"lsm.s/foo", LSM, AttachLSMMac, unix.BPF_F_SLEEPABLE, "foo"},
		{"iter/bpf_map", Tracing, AttachTraceIter, 0, "bpf_map"},
		{"iter.s/", Tracing, AttachTraceIter, unix.BPF_F_SLEEPABLE, ""},
		// Was missing sleepable.
		{"syscall", Syscall, AttachNone, unix.BPF_F_SLEEPABLE, ""},
		{"xdp.frags_devmap/foo", XDP, AttachXDPDevMap, unix.BPF_F_XDP_HAS_FRAGS, "foo"},
		{"xdp_devmap/foo", XDP, AttachXDPDevMap, 0, "foo"},
		{"xdp.frags_cpumap/", XDP, AttachXDPCPUMap, unix.BPF_F_XDP_HAS_FRAGS, ""},
		{"xdp_cpumap/", XDP, AttachXDPCPUMap, 0, ""},
		// Used incorrect attach type.
		{"xdp.frags/foo", XDP, AttachXDP, unix.BPF_F_XDP_HAS_FRAGS, ""},
		{"xdp/foo", XDP, AttachNone, 0, ""},
		{"perf_event", PerfEvent, AttachNone, 0, ""},
		{"lwt_in", LWTIn, AttachNone, 0, ""},
		{"lwt_out", LWTOut, AttachNone, 0, ""},
		{"lwt_xmit", LWTXmit, AttachNone, 0, ""},
		{"lwt_seg6local", LWTSeg6Local, AttachNone, 0, ""},
		{"cgroup_skb/ingress", CGroupSKB, AttachCGroupInetIngress, 0, ""},
		{"cgroup_skb/egress", CGroupSKB, AttachCGroupInetEgress, 0, ""},
		{"cgroup/skb", CGroupSKB, AttachNone, 0, ""},
		{"cgroup/sock_create", CGroupSock, AttachCGroupInetSockCreate, 0, ""},
		{"cgroup/sock_release", CGroupSock, AttachCgroupInetSockRelease, 0, ""},
		{"cgroup/sock", CGroupSock, AttachCGroupInetSockCreate, 0, ""},
		{"cgroup/post_bind4", CGroupSock, AttachCGroupInet4PostBind, 0, ""},
		{"cgroup/post_bind6", CGroupSock, AttachCGroupInet6PostBind, 0, ""},
		{"cgroup/dev", CGroupDevice, AttachCGroupDevice, 0, ""},
		{"sockops", SockOps, AttachCGroupSockOps, 0, ""},
		{"sk_skb/stream_parser", SkSKB, AttachSkSKBStreamParser, 0, ""},
		{"sk_skb/stream_verdict", SkSKB, AttachSkSKBStreamVerdict, 0, ""},
		{"sk_skb/stream_verdict/foo", SkSKB, AttachSkSKBStreamVerdict, 0, ""},
		{"sk_skb", SkSKB, AttachNone, 0, ""},
		{"sk_skb/bar", SkSKB, AttachNone, 0, ""},
		{"sk_msg", SkMsg, AttachSkMsgVerdict, 0, ""},
		{"lirc_mode2", LircMode2, AttachLircMode2, 0, ""},
		{"flow_dissector", FlowDissector, AttachFlowDissector, 0, ""},
		{"cgroup/bind4", CGroupSockAddr, AttachCGroupInet4Bind, 0, ""},
		{"cgroup/bind6", CGroupSockAddr, AttachCGroupInet6Bind, 0, ""},
		{"cgroup/connect4", CGroupSockAddr, AttachCGroupInet4Connect, 0, ""},
		{"cgroup/connect6", CGroupSockAddr, AttachCGroupInet6Connect, 0, ""},
		{"cgroup/sendmsg4", CGroupSockAddr, AttachCGroupUDP4Sendmsg, 0, ""},
		{"cgroup/sendmsg6", CGroupSockAddr, AttachCGroupUDP6Sendmsg, 0, ""},
		{"cgroup/recvmsg4", CGroupSockAddr, AttachCGroupUDP4Recvmsg, 0, ""},
		{"cgroup/recvmsg6", CGroupSockAddr, AttachCGroupUDP6Recvmsg, 0, ""},
		{"cgroup/getpeername4", CGroupSockAddr, AttachCgroupInet4GetPeername, 0, ""},
		{"cgroup/getpeername6", CGroupSockAddr, AttachCgroupInet6GetPeername, 0, ""},
		{"cgroup/getsockname4", CGroupSockAddr, AttachCgroupInet4GetSockname, 0, ""},
		{"cgroup/getsockname6", CGroupSockAddr, AttachCgroupInet6GetSockname, 0, ""},
		{"cgroup/sysctl", CGroupSysctl, AttachCGroupSysctl, 0, ""},
		{"cgroup/getsockopt", CGroupSockopt, AttachCGroupGetsockopt, 0, ""},
		{"cgroup/setsockopt", CGroupSockopt, AttachCGroupSetsockopt, 0, ""},
		// Bogus pattern means it never matched anything.
		// {"struct_ops+", StructOps, AttachNone, 0, ""},
		{"sk_lookup/", SkLookup, AttachSkLookup, 0, ""},
		{"seccomp", SocketFilter, AttachNone, 0, ""},
		{"kprobe.multi", Kprobe, AttachTraceKprobeMulti, 0, ""},
		{"kretprobe.multi", Kprobe, AttachTraceKprobeMulti, 0, ""},
	}

	for _, tc := range testcases {
		t.Run(tc.Section, func(t *testing.T) {
			pt, at, fl, extra := getProgType(tc.Section)
			have := testcase{tc.Section, pt, at, fl, extra}
			qt.Assert(t, qt.DeepEquals(have, tc))
		})
	}
}

func TestMatchSectionName(t *testing.T) {
	for _, testcase := range []struct {
		pattern string
		input   string
		matches bool
		extra   string
	}{
		{"prefix/", "prefix/", true, ""},
		{"prefix/", "prefix/a", true, "a"},
		{"prefix/", "prefix/b", true, "b"},
		{"prefix/", "prefix", false, ""},
		{"prefix/", "junk", false, ""},

		{"prefix+", "prefix/", true, ""},
		{"prefix+", "prefix/a", true, "a"},
		{"prefix+", "prefix/b", true, "b"},
		{"prefix+", "prefix", true, ""},
		{"prefix+", "junk", false, ""},

		{"exact", "exact", true, ""},
		{"exact", "exact/", true, ""},
		{"exact", "exact/a", true, ""},
		{"exact", "exactement", true, ""},
		{"exact", "junk", false, ""},
	} {
		name := fmt.Sprintf("%s:%s", testcase.pattern, testcase.input)
		t.Run(name, func(t *testing.T) {
			extra, matches := matchSectionName(testcase.input, testcase.pattern)
			qt.Assert(t, qt.Equals(matches, testcase.matches))
			if testcase.matches {
				qt.Assert(t, qt.Equals(extra, testcase.extra))
			}
		})
	}
}

// selftestName takes a path to a file and derives a canonical name from it.
//
// It strips various suffixes used by the selftest build system.
func selftestName(path string) string {
	file := filepath.Base(path)

	name := strings.TrimSuffix(file, ".o")
	// Strip various suffixes.
	// Various linking suffixes.
	name = strings.TrimSuffix(name, ".linked3")
	name = strings.TrimSuffix(name, ".llinked1")
	name = strings.TrimSuffix(name, ".llinked2")
	name = strings.TrimSuffix(name, ".llinked3")
	// v6.1 started adding .bpf to all BPF ELF.
	name = strings.TrimSuffix(name, ".bpf")

	return name
}
