package btf

import (
	"fmt"
	"testing"

	qt "github.com/frankban/quicktest"
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
	_, _ = copyType((*Void)(nil), nil)

	in := &Int{Size: 4}
	out, _ := copyType(in, nil)

	in.Size = 8
	if size := out.(*Int).Size; size != 4 {
		t.Error("Copy doesn't make a copy, expected size 4, got", size)
	}

	t.Run("cyclical", func(t *testing.T) {
		_, _ = copyType(newCyclicalType(2), nil)
	})

	t.Run("identity", func(t *testing.T) {
		u16 := &Int{Size: 2}

		out, _ := copyType(&Struct{
			Members: []Member{
				{Name: "a", Type: u16},
				{Name: "b", Type: u16},
			},
		}, nil)

		outStruct := out.(*Struct)
		qt.Assert(t, outStruct.Members[0].Type, qt.Equals, outStruct.Members[1].Type)
	})
}

// The following are valid Types.
//
// There currently is no better way to document which
// types implement an interface.
func ExampleType_validTypes() {
	var _ Type = &Void{}
	var _ Type = &Int{}
	var _ Type = &Pointer{}
	var _ Type = &Array{}
	var _ Type = &Struct{}
	var _ Type = &Union{}
	var _ Type = &Enum{}
	var _ Type = &Fwd{}
	var _ Type = &Typedef{}
	var _ Type = &Volatile{}
	var _ Type = &Const{}
	var _ Type = &Restrict{}
	var _ Type = &Func{}
	var _ Type = &FuncProto{}
	var _ Type = &Var{}
	var _ Type = &Datasec{}
}

func TestType(t *testing.T) {
	types := []func() Type{
		func() Type { return &Void{} },
		func() Type { return &Int{Size: 2, Bits: 3} },
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
			t.Logf("%v", typ)

			if typ == typ.copy() {
				t.Error("Copy doesn't copy")
			}

			var first, second typeDeque
			typ.walk(&first)
			typ.walk(&second)

			if diff := cmp.Diff(first.all(), second.all(), compareTypes); diff != "" {
				t.Errorf("Walk mismatch (-want +got):\n%s", diff)
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
