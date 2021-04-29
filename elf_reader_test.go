package ebpf

import (
	"errors"
	"flag"
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
		},
	}

	defaultOpts := cmp.Options{
		cmpopts.IgnoreTypes(new(btf.Map), new(btf.Program)),
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

		if have.Programs["xdp_prog"].ByteOrder != internal.NativeEndian {
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
		_, err := LoadCollectionSpec(file)
		t.Log(err)
		if err == nil {
			t.Fatal("Loading an invalid map should fail")
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
	testutils.Files(t, testutils.Glob(t, "testdata/initialized_btf_map-*.elf"), func(t *testing.T, file string) {
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

		if spec.Programs["sched_process_exec"].ByteOrder != internal.NativeEndian {
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
		coll, err := NewCollectionWithOptions(spec, opts)
		testutils.SkipIfNotSupported(t, err)
		var errno syscall.Errno
		if errors.As(err, &errno) {
			// This error is most likely from a syscall and caused by us not
			// replicating some fixups done in the selftests. This is expected,
			// so skip the test instead of failing.
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
