package btf

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
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
		func() Type { return &Pointer{Target: &Void{}} },
		func() Type { return &Array{Type: &Int{}} },
		func() Type {
			return &Struct{
				Members: []Member{{Type: &Void{}}},
			}
		},
		func() Type {
			return &Union{
				Members: []Member{{Type: &Void{}}},
			}
		},
		func() Type { return &Enum{} },
		func() Type { return &Fwd{Name: "thunk"} },
		func() Type { return &Typedef{Type: &Void{}} },
		func() Type { return &Volatile{Type: &Void{}} },
		func() Type { return &Const{Type: &Void{}} },
		func() Type { return &Restrict{Type: &Void{}} },
		func() Type { return &Func{Name: "foo", Type: &Void{}} },
		func() Type {
			return &FuncProto{
				Params: []FuncParam{{Name: "bar", Type: &Void{}}},
				Return: &Void{},
			}
		},
		func() Type { return &Var{Type: &Void{}} },
		func() Type {
			return &Datasec{
				Vars: []VarSecinfo{{Type: &Void{}}},
			}
		},
	}

	compareTypes := cmp.Comparer(func(a, b *Type) bool {
		return a == b
	})

	for _, fn := range types {
		typ := fn()
		t.Run(fmt.Sprintf("%T", typ), func(t *testing.T) {
			if typ == typ.copy() {
				t.Error("Copy doesn't copy")
			}

			var first, second copyStack
			typ.walk(&first)
			typ.walk(&second)

			if diff := cmp.Diff(first, second, compareTypes); diff != "" {
				t.Errorf("Walk mismatch (-want +got):\n%s", diff)
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
