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

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/btf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestLoadCollectionSpec(t *testing.T) {
	cpus, err := internal.PossibleCPUs()
	if err != nil {
		t.Fatal(err)
	}

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
				MaxEntries: uint32(cpus),
			},
			// Maps prefixed by btf_ are ignored when testing ELFs
			// that don't have BTF info embedded. (clang<9)
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
		},
		Programs: map[string]*ProgramSpec{
			"xdp_prog": {
				Name:    "xdp_prog",
				Type:    XDP,
				License: "MIT",
			},
			"no_relocation": {
				Name:    "no_relocation",
				Type:    SocketFilter,
				License: "MIT",
			},
			"asm_relocation": {
				Name:    "asm_relocation",
				Type:    SocketFilter,
				License: "MIT",
			},
			"data_sections": {
				Name:    "data_sections",
				Type:    SocketFilter,
				License: "MIT",
			},
		},
	}

	defaultOpts := cmp.Options{
		// Dummy Comparer that works with empty readers to support test cases.
		cmp.Comparer(func(a, b bytes.Reader) bool {
			if a.Len() == 0 && b.Len() == 0 {
				return true
			}
			return false
		}),
		cmpopts.IgnoreTypes(new(btf.Map), new(btf.Program)),
		cmpopts.IgnoreFields(CollectionSpec{}, "ByteOrder"),
		cmpopts.IgnoreFields(ProgramSpec{}, "Instructions", "ByteOrder"),
		cmpopts.IgnoreMapEntries(func(key string, _ *MapSpec) bool {
			switch key {
			case ".bss", ".data", ".rodata":
				return true

			default:
				return false
			}
		}),
	}

	ignoreBTFOpts := append(defaultOpts,
		cmpopts.IgnoreMapEntries(func(key string, _ *MapSpec) bool {
			return strings.HasPrefix(key, "btf_")
		}),
	)

	testutils.Files(t, testutils.Glob(t, "testdata/loader-*.elf"), func(t *testing.T, file string) {
		have, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatal("Can't parse ELF:", err)
		}

		opts := defaultOpts
		if have.Maps[".rodata"] != nil {
			err := have.RewriteConstants(map[string]interface{}{
				"arg": uint32(1),
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
		} else {
			opts = ignoreBTFOpts
		}

		if diff := cmp.Diff(coll, have, opts...); diff != "" {
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

func TestDataSections(t *testing.T) {
	file := fmt.Sprintf("testdata/loader-%s.elf", internal.ClangEndian)
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

	ret, _, err := obj.Program.Test(make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Error("BPF assertion failed on line", ret)
	}
}

func TestInlineASMConstant(t *testing.T) {
	file := fmt.Sprintf("testdata/loader-%s.elf", internal.ClangEndian)
	coll, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	spec := coll.Programs["asm_relocation"]
	if spec.Instructions[0].Reference != "MY_CONST" {
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
	testutils.Files(t, testutils.Glob(t, "testdata/invalid_map-*.elf"), func(t *testing.T, file string) {
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
	})
}

func TestLoadInvalidMapMissingSymbol(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/invalid_map_static-el.elf"), func(t *testing.T, file string) {
		_, err := LoadCollectionSpec(file)
		t.Log(err)
		if err == nil {
			t.Fatal("Loading a map with static qualifier should fail")
		}
	})
}

func TestLoadInitializedBTFMap(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/btf_map_init-*.elf"), func(t *testing.T, file string) {
		coll, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatal(err)
		}

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

			if _, ok := p.Value.(programStub); !ok {
				t.Errorf("expecting MapSpec entry Value to be of type programStub, got %T", p.Value)
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

			p := m.Contents[0]
			if cmp.Equal(p.Key, 1) {
				t.Errorf("expecting MapSpec entry Key to equal 1, got %v", p.Key)
			}

			if _, ok := p.Value.(mapStub); !ok {
				t.Errorf("expecting MapSpec entry Value to be of type mapStub, got %T", p.Value)
			}
		})
	})
}

func TestLoadInvalidInitializedBTFMap(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/invalid_btf_map_init-*.elf"), func(t *testing.T, file string) {
		_, err := LoadCollectionSpec(file)
		t.Log(err)
		if !errors.Is(err, internal.ErrNotSupported) {
			t.Fatal("Loading an initialized BTF map should be unsupported")
		}
	})
}

func TestStringSection(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/strings-*.elf"), func(t *testing.T, file string) {
		_, err := LoadCollectionSpec(file)
		t.Log(err)
		if !errors.Is(err, ErrNotSupported) {
			t.Error("References to a string section should be unsupported")
		}
	})
}

func TestLoadRawTracepoint(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.17", "BPF_RAW_TRACEPOINT API")

	testutils.Files(t, testutils.Glob(t, "testdata/raw_tracepoint-*.elf"), func(t *testing.T, file string) {
		spec, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatal("Can't parse ELF:", err)
		}

		if spec.ByteOrder != internal.NativeEndian {
			return
		}

		coll, err := NewCollectionWithOptions(spec, CollectionOptions{
			Programs: ProgramOptions{
				LogLevel: 1,
			},
		})
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Can't create collection:", err)
		}

		coll.Close()
	})
}

func TestTailCall(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/btf_map_init-*.elf"), func(t *testing.T, file string) {
		spec, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatal(err)
		}

		if spec.ByteOrder != internal.NativeEndian {
			return
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

		ret, _, err := obj.TailMain.Test(make([]byte, 14))
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal(err)
		}

		// Expect the tail_1 tail call to be taken, returning value 42.
		if ret != 42 {
			t.Fatalf("Expected tail call to return value 42, got %d", ret)
		}
	})
}

func TestUnassignedProgArray(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/btf_map_init-*.elf"), func(t *testing.T, file string) {
		spec, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatal(err)
		}

		if spec.ByteOrder != internal.NativeEndian {
			return
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
	})
}

func TestIPRoute2Compat(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/iproute2_map_compat-*.elf"), func(t *testing.T, file string) {
		spec, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatal("Can't parse ELF:", err)
		}

		if spec.ByteOrder != internal.NativeEndian {
			return
		}

		ms, ok := spec.Maps["hash_map"]
		if !ok {
			t.Fatal("Map hash_map not found")
		}

		var id, pinning, innerID, innerIndex uint32

		switch {
		case binary.Read(&ms.Extra, spec.ByteOrder, &id) != nil:
			t.Fatal("missing id")
		case binary.Read(&ms.Extra, spec.ByteOrder, &pinning) != nil:
			t.Fatal("missing pinning")
		case binary.Read(&ms.Extra, spec.ByteOrder, &innerID) != nil:
			t.Fatal("missing inner_id")
		case binary.Read(&ms.Extra, spec.ByteOrder, &innerIndex) != nil:
			t.Fatal("missing inner_idx")
		}

		if id != 0 || innerID != 0 || innerIndex != 0 {
			t.Fatal("expecting id, inner_id and inner_idx to be zero")
		}

		if pinning != 2 {
			t.Fatal("expecting pinning field to be 2 (PIN_GLOBAL_NS)")
		}

		// iproute2 (tc) pins maps in /sys/fs/bpf/tc/globals with PIN_GLOBAL_NS,
		// which needs to be be configured in this library using MapOptions.PinPath.
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
	})
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
		opts.Programs.LogSize = -1

		for name, p := range spec.Programs {
			if p.Type != Extension {
				continue
			}

			targetProg, targetColl := loadTargetProgram(t, name, opts)
			defer targetColl.Close()
			p.AttachTarget = targetProg
		}

		coll, err := NewCollectionWithOptions(spec, opts)
		testutils.SkipIfNotSupported(t, err)
		var errno syscall.Errno
		if errors.As(err, &errno) {
			// This error is most likely from a syscall and caused by us not
			// replicating some fixups done in the selftests or the test
			// intentionally failing. This is expected, so skip the test
			// instead of failing.
			t.Skip("Skipping since the kernel rejected the program:", errno)
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
		file := filepath.Base(path)
		switch file {
		case "test_sk_assign.o":
			t.Skip("Skipping due to incompatible struct bpf_map_def")
		case "test_map_in_map.o", "test_select_reuseport_kern.o":
			t.Skip("Skipping due to missing InnerMap in map definition")
		case "test_core_autosize.o":
			t.Skip("Skipping since the test generates dynamic BTF")
		}

		t.Parallel()

		spec, err := LoadCollectionSpec(path)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatalf("Can't read %s: %s", file, err)
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
			name := filepath.Base(coreFile)
			t.Run(name, func(t *testing.T) {
				// Some files like btf__core_reloc_arrays___err_too_small.o
				// trigger an error on purpose. Use the name to infer whether
				// the test should succeed.
				var valid bool
				switch name {
				case "btf__core_reloc_existence___err_wrong_arr_kind.o",
					"btf__core_reloc_existence___err_wrong_arr_value_type.o",
					"btf__core_reloc_existence___err_wrong_int_kind.o",
					"btf__core_reloc_existence___err_wrong_int_sz.o",
					"btf__core_reloc_existence___err_wrong_int_type.o",
					"btf__core_reloc_existence___err_wrong_struct_type.o":
					// These tests are buggy upstream, see https://lore.kernel.org/bpf/20210420111639.155580-1-lmb@cloudflare.com/
					valid = true
				case "btf__core_reloc_ints___err_wrong_sz_16.o",
					"btf__core_reloc_ints___err_wrong_sz_32.o",
					"btf__core_reloc_ints___err_wrong_sz_64.o",
					"btf__core_reloc_ints___err_wrong_sz_8.o",
					"btf__core_reloc_arrays___err_wrong_val_type1.o",
					"btf__core_reloc_arrays___err_wrong_val_type2.o":
					// These tests are valid according to current libbpf behaviour,
					// see commit 42765ede5c54ca915de5bfeab83be97207e46f68.
					valid = true
				case "btf__core_reloc_type_id___missing_targets.o",
					"btf__core_reloc_flavors__err_wrong_name.o":
					valid = false
				default:
					valid = !strings.Contains(name, "___err_")
				}

				fh, err := os.Open(coreFile)
				if err != nil {
					t.Fatal(err)
				}
				defer fh.Close()

				opts := opts // copy
				opts.Programs.TargetBTF = fh
				load(t, spec, opts, valid)
			})
		}
	})
}

func loadTargetProgram(tb testing.TB, name string, opts CollectionOptions) (*Program, *Collection) {
	file := "test_pkt_access.o"
	program := "test_pkt_access"
	switch name {
	case "new_connect_v4_prog":
		file = "connect4_prog.o"
		program = "connect_v4_prog"
	case "new_do_bind":
		file = "connect4_prog.o"
		program = "connect_v4_prog"
	case "freplace_cls_redirect_test":
		file = "test_cls_redirect.o"
		program = "cls_redirect"
	case "new_handle_kprobe":
		file = "test_attach_probe.o"
		program = "handle_kprobe"
	case "test_pkt_md_access_new":
		file = "test_pkt_md_access.o"
		program = "test_pkt_md_access"
	default:
	}

	spec, err := LoadCollectionSpec(filepath.Join(*elfPath, file))
	if err != nil {
		tb.Fatalf("Can't read %s: %s", file, err)
	}

	coll, err := NewCollectionWithOptions(spec, opts)
	if err != nil {
		tb.Fatalf("Can't load target: %s", err)
	}

	return coll.Programs[program], coll
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

func TestGetProgType(t *testing.T) {
	type progTypeTestData struct {
		Pt ProgramType
		At AttachType
		Fl uint32
		To string
	}

	testcases := map[string]progTypeTestData{
		"socket/garbage": {
			Pt: SocketFilter,
			At: AttachNone,
			To: "",
		},
		"kprobe/func": {
			Pt: Kprobe,
			At: AttachNone,
			To: "func",
		},
		"xdp/foo": {
			Pt: XDP,
			At: AttachNone,
			To: "",
		},
		"cgroup_skb/ingress": {
			Pt: CGroupSKB,
			At: AttachCGroupInetIngress,
			To: "",
		},
		"iter/bpf_map": {
			Pt: Tracing,
			At: AttachTraceIter,
			To: "bpf_map",
		},
		"lsm.s/file_ioctl_sleepable": {
			Pt: LSM,
			At: AttachLSMMac,
			To: "file_ioctl_sleepable",
			Fl: unix.BPF_F_SLEEPABLE,
		},
		"lsm/file_ioctl": {
			Pt: LSM,
			At: AttachLSMMac,
			To: "file_ioctl",
		},
	}

	for section, want := range testcases {
		pt, at, fl, to := getProgType(section)

		if diff := cmp.Diff(want, progTypeTestData{Pt: pt, At: at, Fl: fl, To: to}); diff != "" {
			t.Errorf("getProgType mismatch (-want +got):\n%s", diff)
		}
	}
}
