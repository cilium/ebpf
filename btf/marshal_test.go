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
		Name:     "foo",
		Size:     2,
		Encoding: Signed | Char,
	}

	enc := newEncoder(encoderOptions{ByteOrder: internal.NativeEndian}, nil)

	id, err := enc.Add(typ)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, id, qt.Equals, TypeID(1), qt.Commentf("First non-void type doesn't get id 1"))

	id, err = enc.Add(typ)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, id, qt.Equals, TypeID(1), qt.Commentf("Adding a type twice returns different ids"))

	raw, err := enc.Encode()
	qt.Assert(t, err, qt.IsNil, qt.Commentf("Build returned an error"))

	spec, err := loadRawSpec(bytes.NewReader(raw), internal.NativeEndian, nil, nil)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("Couldn't parse BTF"))

	have, err := spec.AnyTypeByName("foo")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, have, qt.DeepEquals, typ)
}

func TestRoundtripVMlinux(t *testing.T) {
	types := vmlinuxSpec(t).types

	// Randomize the order to force different permutations of walking the type
	// graph.
	rand.Shuffle(len(types), func(i, j int) {
		types[i], types[j] = types[j], types[i]
	})

	b := newEncoder(kernelEncoderOptions, nil)

	for i, typ := range types {
		_, err := b.Add(typ)
		qt.Assert(t, err, qt.IsNil, qt.Commentf("add type #%d: %s", i, typ))

		if b.nextID >= 65_000 {
			// IDs exceeding math.MaxUint16 can trigger a bug when loading BTF.
			// This can be removed once the patch lands.
			// See https://lore.kernel.org/bpf/20220909092107.3035-1-oss@lmb.io/
			break
		}
	}

	nStr := len(b.strings.strings)
	nTypes := len(types)
	t.Log(nStr, "strings", nTypes, "types")
	t.Log(float64(nStr)/float64(nTypes), "avg strings per type")

	raw, err := b.Encode()
	qt.Assert(t, err, qt.IsNil, qt.Commentf("build BTF"))

	rebuilt, err := loadRawSpec(bytes.NewReader(raw), binary.LittleEndian, nil, nil)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("round tripping BTF failed"))

	h, err := NewHandle(rebuilt)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("loading rebuilt BTF failed"))
	h.Close()
}

func BenchmarkBuildVmlinux(b *testing.B) {
	spec := vmlinuxTestdataSpec(b)

	b.ReportAllocs()
	b.ResetTimer()

	types := spec.types
	strings := spec.strings

	for i := 0; i < b.N; i++ {
		enc := newEncoder(encoderOptions{ByteOrder: internal.NativeEndian}, newStringTableBuilderFromTable(strings))

		for _, typ := range types {
			if _, err := enc.Add(typ); err != nil {
				b.Fatal(err)
			}
		}

		_, err := enc.Encode()
		if err != nil {
			b.Fatal(err)
		}
	}
}
