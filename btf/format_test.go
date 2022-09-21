package btf

import (
	"errors"
	"fmt"
	"go/format"
	"strings"
	"testing"
)

func TestGoTypeDeclaration(t *testing.T) {
	tests := []struct {
		typ    Type
		output string
	}{
		{&Int{Size: 1}, "type t uint8"},
		{&Int{Size: 1, Encoding: Bool}, "type t bool"},
		{&Int{Size: 1, Encoding: Char}, "type t uint8"},
		{&Int{Size: 2, Encoding: Signed}, "type t int16"},
		{&Int{Size: 4, Encoding: Signed}, "type t int32"},
		{&Int{Size: 8}, "type t uint64"},
		{&Typedef{Name: "frob", Type: &Int{Size: 8}}, "type t uint64"},
		{&Int{Size: 16}, "type t [16]byte /* uint128 */"},
		{&Enum{Values: []EnumValue{{"FOO", 32}}, Size: 4}, "type t uint32; const ( tFOO t = 32; )"},
		{&Enum{Values: []EnumValue{{"BAR", 1}}, Size: 1, Signed: true}, "type t int8; const ( tBAR t = 1; )"},
		{
			&Struct{
				Name: "enum literals",
				Size: 2,
				Members: []Member{
					{Name: "enum", Type: &Enum{Values: []EnumValue{{"BAR", 1}}, Size: 2}, Offset: 0},
				},
			},
			"type t struct { enum uint16; }",
		},
		{&Array{Nelems: 2, Type: &Int{Size: 1}}, "type t [2]uint8"},
		{
			&Union{
				Size: 8,
				Members: []Member{
					{Name: "a", Type: &Int{Size: 4}},
					{Name: "b", Type: &Int{Size: 8}},
				},
			},
			"type t struct { a uint32; _ [4]byte; }",
		},
		{
			&Struct{
				Name: "field padding",
				Size: 16,
				Members: []Member{
					{Name: "frob", Type: &Int{Size: 4}, Offset: 0},
					{Name: "foo", Type: &Int{Size: 8}, Offset: 8 * 8},
				},
			},
			"type t struct { frob uint32; _ [4]byte; foo uint64; }",
		},
		{
			&Struct{
				Name: "end padding",
				Size: 16,
				Members: []Member{
					{Name: "foo", Type: &Int{Size: 8}, Offset: 0},
					{Name: "frob", Type: &Int{Size: 4}, Offset: 8 * 8},
				},
			},
			"type t struct { foo uint64; frob uint32; _ [4]byte; }",
		},
		{
			&Struct{
				Name: "bitfield",
				Size: 8,
				Members: []Member{
					{Name: "foo", Type: &Int{Size: 4}, Offset: 0, BitfieldSize: 1},
					{Name: "frob", Type: &Int{Size: 4}, Offset: 4 * 8},
				},
			},
			"type t struct { _ [4]byte /* unsupported bitfield */; frob uint32; }",
		},
		{
			&Struct{
				Name: "nested",
				Size: 8,
				Members: []Member{
					{
						Name: "foo",
						Type: &Struct{
							Size: 4,
							Members: []Member{
								{Name: "bar", Type: &Int{Size: 4}, Offset: 0},
							},
						},
					},
					{Name: "frob", Type: &Int{Size: 4}, Offset: 4 * 8},
				},
			},
			"type t struct { foo struct { bar uint32; }; frob uint32; }",
		},
		{
			&Struct{
				Name: "nested anon union",
				Size: 8,
				Members: []Member{
					{
						Name: "",
						Type: &Union{
							Size: 4,
							Members: []Member{
								{Name: "foo", Type: &Int{Size: 4}, Offset: 0},
								{Name: "bar", Type: &Int{Size: 4}, Offset: 0},
							},
						},
					},
				},
			},
			"type t struct { foo uint32; _ [4]byte; }",
		},
		{
			&Datasec{
				Size: 16,
				Vars: []VarSecinfo{
					{&Var{Name: "s", Type: &Int{Size: 2}, Linkage: StaticVar}, 0, 2},
					{&Var{Name: "g", Type: &Int{Size: 4}, Linkage: GlobalVar}, 4, 4},
					{&Var{Name: "e", Type: &Int{Size: 8}, Linkage: ExternVar}, 8, 8},
				},
			},
			"type t struct { _ [4]byte; g uint32; _ [8]byte; }",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprint(test.typ), func(t *testing.T) {
			have := mustGoTypeDeclaration(t, test.typ, nil, nil)
			if have != test.output {
				t.Errorf("Unexpected output:\n\t-%s\n\t+%s", test.output, have)
			}
		})
	}
}

func TestGoTypeDeclarationNamed(t *testing.T) {
	e1 := &Enum{Name: "e1", Size: 4}
	s1 := &Struct{
		Name: "s1",
		Size: 4,
		Members: []Member{
			{Name: "frob", Type: e1},
		},
	}
	s2 := &Struct{
		Name: "s2",
		Size: 4,
		Members: []Member{
			{Name: "frood", Type: s1},
		},
	}
	td := &Typedef{Name: "td", Type: e1}
	arr := &Array{Nelems: 1, Type: td}

	tests := []struct {
		typ    Type
		named  []Type
		output string
	}{
		{e1, []Type{e1}, "type t uint32"},
		{s1, []Type{e1, s1}, "type t struct { frob E1; }"},
		{s2, []Type{e1}, "type t struct { frood struct { frob E1; }; }"},
		{s2, []Type{e1, s1}, "type t struct { frood S1; }"},
		{td, nil, "type t uint32"},
		{td, []Type{td}, "type t uint32"},
		{arr, []Type{td}, "type t [1]TD"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprint(test.typ), func(t *testing.T) {
			names := make(map[Type]string)
			for _, t := range test.named {
				names[t] = strings.ToUpper(t.TypeName())
			}

			have := mustGoTypeDeclaration(t, test.typ, names, nil)
			if have != test.output {
				t.Errorf("Unexpected output:\n\t-%s\n\t+%s", test.output, have)
			}
		})
	}
}

func TestGoTypeDeclarationQualifiers(t *testing.T) {
	i := &Int{Size: 4}
	want := mustGoTypeDeclaration(t, i, nil, nil)

	tests := []struct {
		typ Type
	}{
		{&Volatile{Type: i}},
		{&Const{Type: i}},
		{&Restrict{Type: i}},
	}

	for _, test := range tests {
		t.Run(fmt.Sprint(test.typ), func(t *testing.T) {
			have := mustGoTypeDeclaration(t, test.typ, nil, nil)
			if have != want {
				t.Errorf("Unexpected output:\n\t-%s\n\t+%s", want, have)
			}
		})
	}
}

func TestGoTypeDeclarationCycle(t *testing.T) {
	s := &Struct{Name: "cycle"}
	s.Members = []Member{{Name: "f", Type: s}}

	var gf GoFormatter
	_, err := gf.TypeDeclaration("t", s)
	if !errors.Is(err, errNestedTooDeep) {
		t.Fatal("Expected errNestedTooDeep, got", err)
	}
}

func TestRejectBogusTypes(t *testing.T) {
	tests := []struct {
		typ Type
	}{
		{&Struct{
			Size: 1,
			Members: []Member{
				{Name: "foo", Type: &Int{Size: 2}, Offset: 0},
			},
		}},
		{&Int{Size: 2, Encoding: Bool}},
		{&Int{Size: 1, Encoding: Char | Signed}},
		{&Int{Size: 2, Encoding: Char}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprint(test.typ), func(t *testing.T) {
			var gf GoFormatter

			_, err := gf.TypeDeclaration("t", test.typ)
			if err == nil {
				t.Fatal("TypeDeclaration does not reject bogus type")
			}
		})
	}
}

func mustGoTypeDeclaration(tb testing.TB, typ Type, names map[Type]string, id func(string) string) string {
	tb.Helper()

	gf := GoFormatter{
		Names:      names,
		Identifier: id,
	}

	have, err := gf.TypeDeclaration("t", typ)
	if err != nil {
		tb.Fatal(err)
	}

	_, err = format.Source([]byte(have))
	if err != nil {
		tb.Fatalf("Output can't be formatted: %s\n%s", err, have)
	}

	return have
}
