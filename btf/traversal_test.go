package btf

import (
	"fmt"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestPostorderTraversal(t *testing.T) {
	ptr := newCyclicalType(2).(*Pointer)
	cst := ptr.Target.(*Const)
	str := cst.Type.(*Struct)

	t.Logf("%3v", ptr)
	pending := []Type{str, cst, ptr}
	iter := postorderTraversal(ptr, nil)
	for iter.Next() {
		qt.Assert(t, iter.Type, qt.Equals, pending[0])
		pending = pending[1:]
	}
	qt.Assert(t, pending, qt.HasLen, 0)

	i := &Int{Name: "foo"}
	// i appears twice at the same nesting depth.
	arr := &Array{Index: i, Type: i}
	seen := make(map[Type]bool)
	iter = postorderTraversal(arr, nil)
	for iter.Next() {
		qt.Assert(t, seen[iter.Type], qt.IsFalse)
		seen[iter.Type] = true
	}
	qt.Assert(t, seen[arr], qt.IsTrue)
	qt.Assert(t, seen[i], qt.IsTrue)
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
			iter := postorderTraversal(typ, nil)
			for iter.Next() {
				if seen[iter.Type] {
					t.Fatalf("%s visited twice", iter.Type)
				}
				seen[iter.Type] = true
				last = iter.Type
			}
			if last != typ {
				t.Fatalf("Expected %s got %s as last type", typ, last)
			}

			walkType(typ, func(child *Type) {
				qt.Check(t, seen[*child], qt.IsTrue, qt.Commentf("missing child %s", *child))
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
				iter := postorderTraversal(test.typ, nil)
				for iter.Next() {
				}
			}
		})
	}
}
