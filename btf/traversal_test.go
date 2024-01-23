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
	iter := postorderTraversal(ptr, nil)
	for iter.Next() {
		qt.Assert(t, qt.Equals(iter.Type, pending[0]))
		pending = pending[1:]
	}
	qt.Assert(t, qt.HasLen(pending, 0))

	i := &Int{Name: "foo"}
	// i appears twice at the same nesting depth.
	arr := &Array{Index: i, Type: i}
	seen := make(map[Type]bool)
	iter = postorderTraversal(arr, nil)
	for iter.Next() {
		qt.Assert(t, qt.IsFalse(seen[iter.Type]))
		seen[iter.Type] = true
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
				qt.Check(t, qt.IsTrue(seen[*child]), qt.Commentf("missing child %s", *child))
			})
		})
	}
}

func TestModifyGraph(t *testing.T) {
	a := &Int{}
	b := &Int{}
	skipped := &Int{}
	c := &Pointer{skipped}
	root := &Struct{
		Members: []Member{
			{Type: a},
			{Type: a},
			{Type: b},
			{Type: c},
		},
	}

	counts := make(map[Type]int)
	modifyGraphPreorder(root, func(node Type) (Type, bool) {
		counts[node]++
		if node == c {
			return nil, false
		}
		return node, true
	})

	qt.Assert(t, qt.Equals(counts[root], 1))
	qt.Assert(t, qt.Equals(counts[a], 1))
	qt.Assert(t, qt.Equals(counts[b], 1))
	qt.Assert(t, qt.Equals(counts[c], 1))
	qt.Assert(t, qt.Equals(counts[skipped], 0))

	qt.Assert(t, qt.Equals[Type](root.Members[0].Type, a))
	qt.Assert(t, qt.Equals[Type](root.Members[1].Type, a))
	qt.Assert(t, qt.Equals[Type](root.Members[2].Type, b))
	qt.Assert(t, qt.IsNil(root.Members[3].Type))
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

func BenchmarkPreorderTraversal(b *testing.B) {
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
				modifyGraphPreorder(test.typ, func(t Type) (Type, bool) { return t, true })
			}
		})
	}
}
