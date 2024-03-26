package btf

import (
	"fmt"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestPostorderTraversal(t *testing.T) {
	ptr := newCyclicalType(2).(*Pointer)
	cst := ptr.Target.(*Const)
	str := cst.Type.(*Struct)

	t.Logf("%3v", ptr)
	pending := []Type{str, cst, ptr}
	visitInPostorder(ptr, nil, func(typ Type) bool {
		qt.Assert(t, qt.Equals(typ, pending[0]))
		pending = pending[1:]
		return true
	})
	qt.Assert(t, qt.HasLen(pending, 0))

	i := &Int{Name: "foo"}
	// i appears twice at the same nesting depth.
	arr := &Array{Index: i, Type: i}
	seen := make(map[Type]bool)
	visitInPostorder(arr, nil, func(typ Type) bool {
		qt.Assert(t, qt.IsFalse(seen[typ]))
		seen[typ] = true
		return true
	})
	qt.Assert(t, qt.IsTrue(seen[arr]))
	qt.Assert(t, qt.IsTrue(seen[i]))
}

func TestPostorderTraversalVmlinux(t *testing.T) {
	spec := vmlinuxTestdataSpec(t)

	typ, err := spec.AnyTypeByName("gov_update_cpu_data")
	if err != nil {
		t.Fatal(err)
	}

	for _, typ := range []Type{typ} {
		t.Run(fmt.Sprintf("%s", typ), func(t *testing.T) {
			seen := make(map[Type]bool)
			var last Type
			visitInPostorder(typ, nil, func(typ Type) bool {
				if seen[typ] {
					t.Fatalf("%s visited twice", typ)
				}
				seen[typ] = true
				last = typ
				return true
			})
			if last != typ {
				t.Fatalf("Expected %s got %s as last type", typ, last)
			}

			children(typ, func(child *Type) bool {
				qt.Check(t, qt.IsTrue(seen[*child]), qt.Commentf("missing child %s", *child))
				return true
			})
		})
	}
}

func BenchmarkPostorderTraversal(b *testing.B) {
	spec := vmlinuxTestdataSpec(b)

	var fn *Func
	err := spec.TypeByName("gov_update_cpu_data", &fn)
	if err != nil {
		b.Fatal(err)
	}

	for _, test := range []struct {
		name string
		typ  Type
	}{
		{"single type", &Int{}},
		{"cycle(1)", newCyclicalType(1)},
		{"cycle(10)", newCyclicalType(10)},
		{"gov_update_cpu_data", fn},
	} {
		b.Logf("%10v", test.typ)

		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				visitInPostorder(test.typ, nil, func(t Type) bool { return true })
			}
		})
	}
}
