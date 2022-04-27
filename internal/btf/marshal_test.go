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
	typ := &Int{
		TypeID:   1,
		Name:     "foo",
		Size:     2,
		Encoding: Signed | Char,
	}

	b := newBuilder(internal.NativeEndian, 0)

	id, err := b.Add(typ)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, id, qt.Equals, TypeID(1), qt.Commentf("First non-void type doesn't get id 1"))

	id, err = b.Add(typ)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, id, qt.Equals, TypeID(1), qt.Commentf("Adding a type twice returns different ids"))

	raw, err := b.Build()
	qt.Assert(t, err, qt.IsNil, qt.Commentf("Build returned an error"))

	spec, err := loadRawSpec(bytes.NewReader(raw), internal.NativeEndian, nil, nil)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("Couldn't parse BTF"))

	have, err := spec.AnyTypeByName("foo")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, have, qt.DeepEquals, typ)
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

	b := newBuilder(binary.LittleEndian, 0)
	b.StripFuncLinkage = haveFuncLinkage() != nil

	for i, typ := range types {
		_, err := b.Add(typ)
		qt.Assert(t, err, qt.IsNil, qt.Commentf("add type #%d: %s", i, typ))
	}

	nStr := len(b.strings.strings)
	nTypes := len(types)
	t.Log(len(b.strings.strings), "strings", nTypes, "types")
	t.Log(float64(nStr)/float64(nTypes), "avg strings per type")

	raw, err := b.Build()
	qt.Assert(t, err, qt.IsNil, qt.Commentf("build BTF"))

	rebuilt, err := loadRawSpec(bytes.NewReader(raw), binary.LittleEndian, nil, nil)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("round tripping BTF failed"))
	qt.Assert(t, len(rebuilt.types), qt.Equals, nTypes)

	h, err := NewHandle(rebuilt)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("loading rebuilt BTF failed"))
	h.Close()
}

func BenchmarkBuildVmlinux(b *testing.B) {
	spec := parseVMLinuxTypes(b)

	b.Run("builder", func(b *testing.B) {
		b.ReportAllocs()

		types := spec.types

		for i := 0; i < b.N; i++ {
			builder := newBuilder(binary.LittleEndian, len(types))

			for _, typ := range types {
				if _, err := builder.Add(typ); err != nil {
					b.Fatal(err)
				}
			}

			_, err := builder.Build()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("native", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := spec.marshal(marshalOpts{ByteOrder: binary.LittleEndian})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
