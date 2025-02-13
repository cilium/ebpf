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
	for typ := range postorder(ptr, nil) {
		qt.Assert(t, qt.Equals(typ, pending[0]))
		pending = pending[1:]
	}
	qt.Assert(t, qt.HasLen(pending, 0))

	i := &Int{Name: "foo"}
	// i appears twice at the same nesting depth.
	arr := &Array{Index: i, Type: i}
	seen := make(map[Type]bool)
	for typ := range postorder(arr, nil) {
		qt.Assert(t, qt.IsFalse(seen[typ]))
		seen[typ] = true
	}
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
			for typ := range postorder(typ, nil) {
				if seen[typ] {
					t.Fatalf("%s visited twice", typ)
				}
				seen[typ] = true
				last = typ
			}
			if last != typ {
				t.Fatalf("Expected %s got %s as last type", typ, last)
			}

			for child := range children(typ) {
				qt.Check(t, qt.IsTrue(seen[*child]), qt.Commentf("missing child %s", *child))
			}
		})
	}
}

func TestChildren(t *testing.T) {
	for _, test := range []struct {
		typ   Type
		count int
	}{
		{&Int{}, 0},
		{&Const{&Int{}}, 1},
		{&Array{Index: &Int{}, Type: &Int{}}, 2},
	} {
		t.Run(fmt.Sprint(test.typ), func(t *testing.T) {
			var count int
			allocs := testing.AllocsPerRun(1, func() {
				count = 0
				for range children(test.typ) {
					count++
				}
			})
			qt.Assert(t, qt.Equals(count, test.count))
			qt.Assert(t, qt.Equals(allocs, 0))
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
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for range postorder(test.typ, nil) {
				}
			}
		})
	}
}
