package btf

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf/internal"

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

func TestPow(t *testing.T) {
	tests := []struct {
		n int
		r bool
	}{
		{0, false},
		{1, true},
		{2, true},
		{3, false},
		{4, true},
		{5, false},
		{8, true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.n), func(t *testing.T) {
			if want, got := tt.r, pow(tt.n); want != got {
				t.Errorf("unexpected result for n %d; want: %v, got: %v", tt.n, want, got)
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

func TestAs(t *testing.T) {
	i := &Int{}
	ptr := &Pointer{i}
	td := &Typedef{Type: ptr}
	cst := &Const{td}
	vol := &Volatile{cst}

	// It's possible to retrieve qualifiers and Typedefs.
	haveVol, ok := as[*Volatile](vol)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, haveVol, qt.Equals, vol)

	haveTd, ok := as[*Typedef](vol)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, haveTd, qt.Equals, td)

	haveCst, ok := as[*Const](vol)
	qt.Assert(t, ok, qt.IsTrue)
	qt.Assert(t, haveCst, qt.Equals, cst)

	// Make sure we don't skip Pointer.
	haveI, ok := as[*Int](vol)
	qt.Assert(t, ok, qt.IsFalse)
	qt.Assert(t, haveI, qt.IsNil)

	// Make sure we can always retrieve Pointer.
	for _, typ := range []Type{
		td, cst, vol, ptr,
	} {
		have, ok := as[*Pointer](typ)
		qt.Assert(t, ok, qt.IsTrue)
		qt.Assert(t, have, qt.Equals, ptr)
	}
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
	var _ Type = &Float{}
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
		func() Type { return &Float{} },
		func() Type { return &declTag{Type: &Void{}} },
		func() Type { return &typeTag{Type: &Void{}} },
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

			var a []*Type
			walkType(typ, func(t *Type) { a = append(a, t) })

			if _, ok := typ.(*cycle); !ok {
				if n := countChildren(t, reflect.TypeOf(typ)); len(a) < n {
					t.Errorf("walkType visited %d children, expected at least %d", len(a), n)
				}
			}

			var b []*Type
			walkType(typ, func(t *Type) { b = append(b, t) })

			if diff := cmp.Diff(a, b, compareTypes); diff != "" {
				t.Errorf("Walk mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTagMarshaling(t *testing.T) {
	for _, typ := range []Type{
		&declTag{&Struct{Members: []Member{}}, "foo", -1},
		&typeTag{&Int{}, "foo"},
	} {
		t.Run(fmt.Sprint(typ), func(t *testing.T) {
			buf := marshalNativeEndian(t, []Type{typ})

			s, err := loadRawSpec(bytes.NewReader(buf), internal.NativeEndian, nil)
			qt.Assert(t, err, qt.IsNil)

			have, err := s.TypeByID(1)
			qt.Assert(t, err, qt.IsNil)

			qt.Assert(t, have, qt.DeepEquals, typ)
		})
	}
}

func countChildren(t *testing.T, typ reflect.Type) int {
	if typ.Kind() != reflect.Pointer {
		t.Fatal("Expected pointer, got", typ.Kind())
	}

	typ = typ.Elem()
	if typ.Kind() != reflect.Struct {
		t.Fatal("Expected struct, got", typ.Kind())
	}

	var n int
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type == reflect.TypeOf((*Type)(nil)).Elem() {
			n++
		}
	}

	return n
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
			prev = &Array{Type: prev, Index: &Int{Size: 1}}
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
		{"type tag", func(t Type) Type { return &typeTag{Type: t} }},
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
			types, err := inflateRawTypes(test.raw, emptyStrings, nil)
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

func BenchmarkWalk(b *testing.B) {
	types := []Type{
		&Void{},
		&Int{},
		&Pointer{},
		&Array{},
		&Struct{Members: make([]Member, 2)},
		&Union{Members: make([]Member, 2)},
		&Enum{},
		&Fwd{},
		&Typedef{},
		&Volatile{},
		&Const{},
		&Restrict{},
		&Func{},
		&FuncProto{Params: make([]FuncParam, 2)},
		&Var{},
		&Datasec{Vars: make([]VarSecinfo, 2)},
	}

	for _, typ := range types {
		b.Run(fmt.Sprint(typ), func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				var dq typeDeque
				walkType(typ, dq.Push)
			}
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
