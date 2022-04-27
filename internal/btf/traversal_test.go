package btf

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

func init() {
	seed := time.Now().UnixMicro()
	fmt.Println("seed:", seed)
	rand.Seed(seed)
}

func TestPreorderTraversal(t *testing.T) {
	ptr := newCyclicalType(2).(*Pointer)
	cst := ptr.Target.(*Const)
	str := cst.Type.(*Struct)

	t.Logf("%3v", ptr)
	types := preorderTraversal(ptr, nil)
	qt.Assert(t, types, qt.HasLen, 3)
	qt.Assert(t, types[0], qt.Equals, str)
	qt.Assert(t, types[1], qt.Equals, cst)
	qt.Assert(t, types[2], qt.Equals, ptr)

	types = preorderTraversal(ptr, func(t Type) bool { return t == cst })
	qt.Assert(t, types, qt.HasLen, 1)
	qt.Assert(t, types[0], qt.Equals, ptr)

	types = preorderTraversal(ptr, func(t Type) bool { return t == ptr })
	qt.Assert(t, types, qt.HasLen, 0)

	i := &Int{Name: "foo"}
	// i appears twice at the same nesting depth.
	arr := &Array{Index: i, Type: i}
	types = preorderTraversal(arr, nil)
	qt.Assert(t, types, qt.HasLen, 2)
	qt.Assert(t, types[0], qt.Equals, i)
	qt.Assert(t, types[1], qt.Equals, arr)
}

func TestPreorderTraversalVmlinux(t *testing.T) {
	types := parseVMLinuxTypes(t).types

	rand.Shuffle(len(types), func(i, j int) {
		types[i], types[j] = types[j], types[i]
	})

	for _, typ := range types[:500] {
		t.Run(fmt.Sprintf("%s", typ), func(t *testing.T) {
			types := preorderTraversal(typ, nil)

			var children typeDeque
			walkType(typ, children.push)

			positions := make(map[Type]int)
			for pos, result := range types {
				if _, ok := positions[result]; ok {
					t.Errorf("%s returned multiple times", result)
				}
				positions[result] = pos
			}

			qt.Check(t, positions[typ], qt.Equals, len(types)-1, qt.Commentf("type isn't last"))
			for _, child := range children.all() {
				_, present := positions[*child]
				qt.Check(t, present, qt.IsTrue, qt.Commentf("missing child %s", *child))
			}
		})
	}
}

func BenchmarkPreorderTraversal(b *testing.B) {
	for _, test := range []struct {
		name string
		typ  Type
	}{
		{"single type", &Int{}},
		{"cycle(1)", newCyclicalType(1)},
		{"cycle(10)", newCyclicalType(10)},
	} {
		b.Logf("%10v", test.typ)

		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				preorderTraversal(test.typ, nil)
			}
		})
	}
}

func TestTypeDeque(t *testing.T) {
	a, b := new(Type), new(Type)

	t.Run("pop", func(t *testing.T) {
		var td typeDeque
		td.push(a)
		td.push(b)

		if td.pop() != b {
			t.Error("Didn't pop b first")
		}

		if td.pop() != a {
			t.Error("Didn't pop a second")
		}

		if td.pop() != nil {
			t.Error("Didn't pop nil")
		}
	})

	t.Run("shift", func(t *testing.T) {
		var td typeDeque
		td.push(a)
		td.push(b)

		if td.shift() != a {
			t.Error("Didn't shift a second")
		}

		if td.shift() != b {
			t.Error("Didn't shift b first")
		}

		if td.shift() != nil {
			t.Error("Didn't shift nil")
		}
	})

	t.Run("push", func(t *testing.T) {
		var td typeDeque
		td.push(a)
		td.push(b)
		td.shift()

		ts := make([]Type, 12)
		for i := range ts {
			td.push(&ts[i])
		}

		if td.shift() != b {
			t.Error("Didn't shift b first")
		}
		for i := range ts {
			if td.shift() != &ts[i] {
				t.Fatal("Shifted wrong Type at pos", i)
			}
		}
	})

	t.Run("all", func(t *testing.T) {
		var td typeDeque
		td.push(a)
		td.push(b)

		all := td.all()
		if len(all) != 2 {
			t.Fatal("Expected 2 elements, got", len(all))
		}

		if all[0] != a || all[1] != b {
			t.Fatal("Elements don't match")
		}
	})
}

var vmlinuxTypes struct {
	sync.Once
	spec *Spec
	err  error
}

func parseVMLinuxTypes(tb testing.TB) *Spec {
	tb.Helper()

	vmlinuxTypes.Do(func() {
		vmlinuxTypes.spec, vmlinuxTypes.err = loadRawSpec(readVMLinux(tb), binary.LittleEndian, nil, nil)
	})

	if err := vmlinuxTypes.err; err != nil {
		tb.Fatal("Failed to parse vmlinux types:", err)
	}

	return vmlinuxTypes.spec.Copy()
}
