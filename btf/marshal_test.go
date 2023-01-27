package btf

import (
	"bytes"
	"encoding/binary"
	"math"
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

	want := []Type{
		(*Void)(nil),
		typ,
		&Pointer{typ},
		&Typedef{"baz", typ},
	}

	var buf bytes.Buffer
	qt.Assert(t, marshalTypes(&buf, want, nil, nil), qt.IsNil)

	have, err := loadRawSpec(bytes.NewReader(buf.Bytes()), internal.NativeEndian, nil, nil)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("Couldn't parse BTF"))
	qt.Assert(t, have.types, qt.DeepEquals, want)
}

func TestRoundtripVMlinux(t *testing.T) {
	types := vmlinuxSpec(t).types

	// Randomize the order to force different permutations of walking the type
	// graph. Keep Void at index 0.
	rand.Shuffle(len(types[1:]), func(i, j int) {
		types[i+1], types[j+1] = types[j+1], types[i+1]
	})

	// Skip per CPU datasec, see https://github.com/cilium/ebpf/issues/921
	for i, typ := range types {
		if ds, ok := typ.(*Datasec); ok && ds.Name == ".data..percpu" {
			types[i] = types[len(types)-1]
			types = types[:len(types)-1]
			break
		}
	}

	seen := make(map[Type]bool)
limitTypes:
	for i, typ := range types {
		iter := postorderTraversal(typ, func(t Type) (skip bool) {
			return seen[t]
		})
		for iter.Next() {
			seen[iter.Type] = true
		}
		if len(seen) >= math.MaxInt16 {
			// IDs exceeding math.MaxUint16 can trigger a bug when loading BTF.
			// This can be removed once the patch lands.
			// See https://lore.kernel.org/bpf/20220909092107.3035-1-oss@lmb.io/
			types = types[:i]
			break limitTypes
		}
	}

	var buf bytes.Buffer
	qt.Assert(t, marshalTypes(&buf, types, nil, nil), qt.IsNil)

	rebuilt, err := loadRawSpec(bytes.NewReader(buf.Bytes()), binary.LittleEndian, nil, nil)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("round tripping BTF failed"))

	if n := len(rebuilt.types); n > math.MaxUint16 {
		t.Logf("Rebuilt BTF contains %d types which exceeds uint16, test may fail on older kernels", n)
	}

	h, err := NewHandle(rebuilt)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("loading rebuilt BTF failed"))
	h.Close()
}

func BenchmarkBuildVmlinux(b *testing.B) {
	types := vmlinuxTestdataSpec(b).types

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := marshalTypes(&buf, types, nil, nil); err != nil {
			b.Fatal(err)
		}
	}
}
