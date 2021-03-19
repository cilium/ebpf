package ebpf

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
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

	testutils.TestFiles(t, "testdata/loader-*.elf", func(t *testing.T, file string) {
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
	testutils.TestFiles(t, "testdata/invalid_map-*.elf", func(t *testing.T, file string) {
		_, err := LoadCollectionSpec(file)
		t.Log(err)
		if err == nil {
			t.Fatal("Loading an invalid map should fail")
		}
	})
}

func TestLoadInvalidMapMissingSymbol(t *testing.T) {
	testutils.TestFiles(t, "testdata/invalid_map_static-el.elf", func(t *testing.T, file string) {
		_, err := LoadCollectionSpec(file)
		t.Log(err)
		if err == nil {
			t.Fatal("Loading a map with static qualifier should fail")
		}
	})
}

func TestLoadInitializedBTFMap(t *testing.T) {
	testutils.TestFiles(t, "testdata/initialized_btf_map-*.elf", func(t *testing.T, file string) {
		_, err := LoadCollectionSpec(file)
		t.Log(err)
		if !errors.Is(err, internal.ErrNotSupported) {
			t.Fatal("Loading an initialized BTF map should be unsupported")
		}
	})
}

func TestStringSection(t *testing.T) {
	testutils.TestFiles(t, "testdata/strings-*.elf", func(t *testing.T, file string) {
		_, err := LoadCollectionSpec(file)
		t.Log(err)
		if !errors.Is(err, ErrNotSupported) {
			t.Error("References to a string section should be unsupported")
		}
		if !strings.Contains(err.Error(), ".L.str") {
			t.Error("Error should contain symbol name")
		}
	})
}

func TestLoadRawTracepoint(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.17", "BPF_RAW_TRACEPOINT API")

	testutils.TestFiles(t, "testdata/raw_tracepoint-*.elf", func(t *testing.T, file string) {
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

	testutils.TestFiles(t, filepath.Join(*elfPath, *elfPattern), func(t *testing.T, path string) {
		file := filepath.Base(path)
		switch file {
		case "test_ksyms.o":
			// Issue #114
			t.Skip("Kernel symbols not supported")
		case "test_sk_assign.o":
			t.Skip("Incompatible struct bpf_map_def")
		case "test_ringbuf_multi.o", "map_ptr_kern.o", "test_btf_map_in_map.o":
			// Issue #155
			t.Skip("BTF .values not supported")
		}

		t.Parallel()

		_, err := LoadCollectionSpec(path)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatalf("Can't read %s: %s", file, err)
		}
	})
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
