package btf

import (
	"fmt"
	"testing"
)

func TestSizeof(t *testing.T) {
	testcases := []struct {
		size int
		typ  Type
	}{
		{0, (*Void)(nil)},
		{1, &Int{Size: 1}},
		{4, &Enum{}},
		{0, &Array{Type: &Pointer{Target: (*Void)(nil)}, Nelems: 0}},
		{12, &Array{Type: &Enum{}, Nelems: 3}},
	}

	for _, tc := range testcases {
		name := fmt.Sprint(tc.typ)
		t.Run(name, func(t *testing.T) {
			have, err := Sizeof(tc.typ)
			if err != nil {
				t.Fatal("Can't calculate size:", err)
			}
			if have != tc.size {
				t.Errorf("Expected size %d, got %d", tc.size, have)
			}
		})
	}
}

func TestCopyType(t *testing.T) {
	_ = copyType((*Void)(nil))

	in := &Int{Size: 4}
	out := copyType(in)

	in.Size = 8
	if size := out.(*Int).Size; size != 4 {
		t.Error("Copy doesn't make a copy, expected size 4, got", size)
	}

	t.Run("cyclical", func(t *testing.T) {
		_ = copyType(newCyclicalType(2))
	})
}

// The following are valid Types.
//
// There currently is no better way to document which
// types implement an interface.
func ExampleType_validTypes() {
	var t Type
	t = &Void{}
	t = &Int{}
	t = &Pointer{}
	t = &Array{}
	t = &Struct{}
	t = &Union{}
	t = &Enum{}
	t = &Fwd{}
	t = &Typedef{}
	t = &Volatile{}
	t = &Const{}
	t = &Restrict{}
	t = &Func{}
	t = &FuncProto{}
	t = &Var{}
	t = &Datasec{}
	_ = t
}

func TestType(t *testing.T) {
	types := []func() Type{
		func() Type { return &Void{} },
		func() Type { return &Int{} },
		func() Type { return &Pointer{} },
		func() Type { return &Array{} },
		func() Type { return &Struct{} },
		func() Type { return &Union{} },
		func() Type { return &Enum{} },
		func() Type { return &Fwd{} },
		func() Type { return &Typedef{} },
		func() Type { return &Volatile{} },
		func() Type { return &Const{} },
		func() Type { return &Restrict{} },
		func() Type { return &Func{} },
		func() Type { return &FuncProto{} },
		func() Type { return &Var{} },
		func() Type { return &Datasec{} },
	}

	for _, fn := range types {
		typ := fn()
		t.Run(fmt.Sprintf("%T", typ), func(t *testing.T) {
			if typ == typ.copy() {
				t.Error("Copy doesn't copy")
			}

			var first, second copyStack
			typ.walk(&first)
			typ.walk(&second)

			a, b := first.pop(), second.pop()
			for a != nil && b != nil {
				if a != b {
					t.Fatal("Order of walk is not the same")
				}
				a, b = first.pop(), second.pop()
			}

			if a != nil || b != nil {
				t.Fatal("Number of types walked is not the same")
			}
		})
	}
}

func newCyclicalType(n int) Type {
	ptr := &Pointer{}
	prev := Type(ptr)
	for i := 0; i < n; i++ {
		switch i % 5 {
		case 0:
			prev = &Struct{
				Members: []Member{
					{Type: prev},
				},
			}

		case 1:
			prev = &Const{Type: prev}
		case 2:
			prev = &Volatile{Type: prev}
		case 3:
			prev = &Typedef{Type: prev}
		case 4:
			prev = &Array{Type: prev}
		}
	}
	ptr.Target = prev
	return ptr
}
