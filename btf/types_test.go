package btf

import (
	"fmt"
	"reflect"
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
		{8, &Enum{Size: 8}},
		{0, &Array{Type: &Pointer{Target: (*Void)(nil)}, Nelems: 0}},
		{12, &Array{Type: &Enum{Size: 4}, Nelems: 3}},
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

func TestCopy(t *testing.T) {
	_ = Copy((*Void)(nil), nil)

	in := &Int{Size: 4}
	out := Copy(in, nil)

	in.Size = 8
	if size := out.(*Int).Size; size != 4 {
		t.Error("Copy doesn't make a copy, expected size 4, got", size)
	}

	t.Run("cyclical", func(t *testing.T) {
		_ = Copy(newCyclicalType(2), nil)
	})

	t.Run("identity", func(t *testing.T) {
		u16 := &Int{Size: 2}

		out := Copy(&Struct{
			Members: []Member{
				{Name: "a", Type: u16},
				{Name: "b", Type: u16},
			},
		}, nil)

		outStruct := out.(*Struct)
		qt.Assert(t, outStruct.Members[0].Type, qt.Equals, outStruct.Members[1].Type)
	})
}

func BenchmarkCopy(b *testing.B) {
	typ := newCyclicalType(10)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Copy(typ, nil)
	}
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
		func() Type { return &Int{Size: 2} },
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
		func() Type { return &cycle{&Void{}} },
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

type testFormattableType struct {
	name  string
	extra []interface{}
}

var _ formattableType = (*testFormattableType)(nil)

func (tft *testFormattableType) TypeName() string { return tft.name }
func (tft *testFormattableType) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, tft, tft.extra...)
}

func TestFormatType(t *testing.T) {
	t1 := &testFormattableType{"", []interface{}{"extra"}}
	t1Addr := fmt.Sprintf("%#p", t1)
	goType := reflect.TypeOf(t1).Elem().Name()

	t2 := &testFormattableType{"foo", []interface{}{t1}}

	t3 := &testFormattableType{extra: []interface{}{""}}

	tests := []struct {
		t        formattableType
		fmt      string
		contains []string
		omits    []string
	}{
		// %s doesn't contain address or extra.
		{t1, "%s", []string{goType}, []string{t1Addr, "extra"}},
		// %+s doesn't contain extra.
		{t1, "%+s", []string{goType, t1Addr}, []string{"extra"}},
		// %v does contain extra.
		{t1, "%v", []string{goType, "extra"}, []string{t1Addr}},
		// %+v does contain address.
		{t1, "%+v", []string{goType, "extra", t1Addr}, nil},
		// %v doesn't print nested types' extra.
		{t2, "%v", []string{goType, t2.name}, []string{"extra"}},
		// %1v does print nested types' extra.
		{t2, "%1v", []string{goType, t2.name, "extra"}, nil},
		// empty strings in extra don't emit anything.
		{t3, "%v", []string{"[]"}, nil},
	}

	for _, test := range tests {
		t.Run(test.fmt, func(t *testing.T) {
			str := fmt.Sprintf(test.fmt, test.t)
			t.Log(str)

			for _, want := range test.contains {
				qt.Assert(t, str, qt.Contains, want)
			}

			for _, notWant := range test.omits {
				qt.Assert(t, str, qt.Not(qt.Contains), notWant)
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

func TestUnderlyingType(t *testing.T) {
	wrappers := []struct {
		name string
		fn   func(Type) Type
	}{
		{"const", func(t Type) Type { return &Const{Type: t} }},
		{"volatile", func(t Type) Type { return &Volatile{Type: t} }},
		{"restrict", func(t Type) Type { return &Restrict{Type: t} }},
		{"typedef", func(t Type) Type { return &Typedef{Type: t} }},
	}

	for _, test := range wrappers {
		t.Run(test.name+" cycle", func(t *testing.T) {
			root := &Volatile{}
			root.Type = test.fn(root)

			got, ok := UnderlyingType(root).(*cycle)
			qt.Assert(t, ok, qt.IsTrue)
			qt.Assert(t, got.root, qt.Equals, root)
		})
	}

	for _, test := range wrappers {
		t.Run(test.name, func(t *testing.T) {
			want := &Int{}
			got := UnderlyingType(test.fn(want))
			qt.Assert(t, got, qt.Equals, want)
		})
	}
}

func TestInflateLegacyBitfield(t *testing.T) {
	const offset = 3
	const size = 5

	var rawInt rawType
	rawInt.SetKind(kindInt)
	rawInt.SetSize(4)
	var data btfInt
	data.SetOffset(offset)
	data.SetBits(size)
	rawInt.data = &data

	var beforeInt rawType
	beforeInt.SetKind(kindStruct)
	beforeInt.SetVlen(1)
	beforeInt.data = []btfMember{{Type: 2}}

	afterInt := beforeInt
	afterInt.data = []btfMember{{Type: 1}}

	emptyStrings := newStringTable("")

	for _, test := range []struct {
		name string
		raw  []rawType
	}{
		{"struct before int", []rawType{beforeInt, rawInt}},
		{"struct after int", []rawType{rawInt, afterInt}},
	} {
		t.Run(test.name, func(t *testing.T) {
			types, err := inflateRawTypes(test.raw, nil, emptyStrings)
			if err != nil {
				t.Fatal(err)
			}

			for _, typ := range types {
				s, ok := typ.(*Struct)
				if !ok {
					continue
				}

				i := s.Members[0]
				if i.BitfieldSize != size {
					t.Errorf("Expected bitfield size %d, got %d", size, i.BitfieldSize)
				}

				if i.Offset != offset {
					t.Errorf("Expected offset %d, got %d", offset, i.Offset)
				}

				return
			}

			t.Fatal("No Struct returned from inflateRawTypes")
		})
	}
}

func BenchmarkUnderlyingType(b *testing.B) {
	b.Run("no unwrapping", func(b *testing.B) {
		v := &Int{}
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			UnderlyingType(v)
		}
	})

	b.Run("single unwrapping", func(b *testing.B) {
		v := &Typedef{Type: &Int{}}
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			UnderlyingType(v)
		}
	})
}

// Copy can be used with UnderlyingType to strip qualifiers from a type graph.
func ExampleCopy_stripQualifiers() {
	a := &Volatile{Type: &Pointer{Target: &Typedef{Name: "foo", Type: &Int{Size: 2}}}}
	b := Copy(a, UnderlyingType)
	// b has Volatile and Typedef removed.
	fmt.Printf("%3v\n", b)
	// Output: Pointer[target=Int[unsigned size=16]]
}
