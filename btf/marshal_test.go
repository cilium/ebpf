package btf

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"

	qt "github.com/frankban/quicktest"
)

func TestBuild(t *testing.T) {
	i := &Int{
		Name:     "foo",
		Size:     2,
		Encoding: Signed | Char,
	}

	want := NewSpec()
	for _, typ := range []Type{
		i,
		&Pointer{i},
		&Typedef{"baz", i},
	} {
		_, err := want.Add(typ)
		qt.Assert(t, err, qt.IsNil)
	}

	var buf bytes.Buffer
	qt.Assert(t, marshalTypes(&buf, want, nil, nil), qt.IsNil)

	have, err := loadRawSpec(bytes.NewReader(buf.Bytes()), internal.NativeEndian, nil)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("Couldn't parse BTF"))
	qt.Assert(t, have.types, qt.DeepEquals, want.types)
}

func TestBuildVmlinux(t *testing.T) {
	spec := parseVMLinuxTypes(t)

	noFloat := testutils.MustKernelVersion().Less(internal.Version{5, 13, 0})
	types := make([]Type, 0, len(spec.types))
	for _, typ := range spec.types {
		if noFloat {
			if _, ok := typ.(*Float); ok {
				// Skip floats on pre-5.13 kernels.
				continue
			}
		}

		types = append(types, typ)
	}

	// Randomize the order to force different permutations of walking the type
	// graph.
	rand.Shuffle(len(types), func(i, j int) {
		types[i], types[j] = types[j], types[i]
	})

	s := NewSpec()
	for _, typ := range types {
		id, err := s.Add(typ)
		qt.Assert(t, err, qt.IsNil)

		if id >= 65_000 {
			// IDs exceeding math.MaxUint16 can trigger a bug when loading BTF.
			// This can be removed once the patch lands.
			// See https://lore.kernel.org/bpf/20220909092107.3035-1-oss@lmb.io/
			break
		}
	}

	var buf bytes.Buffer
	qt.Assert(t, marshalTypes(&buf, s, nil, nil), qt.IsNil)

	rebuilt, err := loadRawSpec(bytes.NewReader(buf.Bytes()), binary.LittleEndian, nil)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("round tripping BTF failed"))

	h, err := NewHandle(rebuilt)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("loading rebuilt BTF failed"))
	h.Close()
}

func BenchmarkBuildVmlinux(b *testing.B) {
	spec := parseVMLinuxTypes(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		err := marshalTypes(&buf, spec, nil, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
