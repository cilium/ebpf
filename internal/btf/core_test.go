package btf

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestCoreAreTypesCompatible(t *testing.T) {
	tests := []struct {
		a, b       Type
		compatible bool
	}{
		{&Void{}, &Void{}, true},
		{&Struct{Name: "a"}, &Struct{Name: "b"}, true},
		{&Union{Name: "a"}, &Union{Name: "b"}, true},
		{&Union{Name: "a"}, &Struct{Name: "b"}, false},
		{&Enum{Name: "a"}, &Enum{Name: "b"}, true},
		{&Fwd{Name: "a"}, &Fwd{Name: "b"}, true},
		{&Int{Name: "a", Size: 2}, &Int{Name: "b", Size: 4}, true},
		{&Int{Offset: 1}, &Int{}, false},
		{&Pointer{Target: &Void{}}, &Pointer{Target: &Void{}}, true},
		{&Pointer{Target: &Void{}}, &Void{}, false},
		{&Array{Type: &Void{}}, &Array{Type: &Void{}}, true},
		{&Array{Type: &Int{}}, &Array{Type: &Void{}}, false},
		{&FuncProto{Return: &Int{}}, &FuncProto{Return: &Void{}}, false},
		{
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Name: "a", Type: &Void{}}}},
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Name: "b", Type: &Void{}}}},
			true,
		},
		{
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Type: &Void{}}}},
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Type: &Int{}}}},
			false,
		},
		{
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Type: &Void{}}, {Type: &Void{}}}},
			&FuncProto{Return: &Void{}, Params: []FuncParam{{Type: &Void{}}}},
			false,
		},
		{&Typedef{Name: "a", Type: &Void{}}, &Void{}, true},
		{&Typedef{Name: "a", Type: &Void{}}, &Int{}, false},
		{&Const{Type: &Void{}}, &Void{}, true},
		{&Const{Type: &Void{}}, &Int{}, false},
		{&Volatile{Type: &Void{}}, &Void{}, true},
		{&Volatile{Type: &Void{}}, &Int{}, false},
		{&Restrict{Type: &Void{}}, &Void{}, true},
		{&Restrict{Type: &Void{}}, &Int{}, false},
	}

	for _, test := range tests {
		compatible, err := coreAreTypesCompatible(test.a, test.b)
		if err != nil {
			t.Errorf("Can't compare types: %s\na = %#v\nb = %#v", err, test.a, test.b)
			continue
		}

		if compatible != test.compatible {
			if test.compatible {
				t.Errorf("Expected types to be compatible:\na = %#v\nb = %#v", test.a, test.b)
			} else {
				t.Errorf("Expected types to be incompatible:\na = %#v\nb = %#v", test.a, test.b)
			}
			continue
		}

		compatibleReverse, err := coreAreTypesCompatible(test.b, test.a)
		if err != nil {
			t.Errorf("Can't compare reversed types: %s\na = %#v\nb = %#v", err, test.a, test.b)
			continue
		}
		if compatibleReverse != compatible {
			t.Errorf("Expected the reverse comparison to be %v as well:\na = %#v\nb = %#v", compatible, test.a, test.b)
		}
	}

	for _, invalid := range []Type{&Var{}, &Datasec{}} {
		_, err := coreAreTypesCompatible(invalid, invalid)
		if err == nil {
			t.Errorf("Expected an error for %T", invalid)
		}
	}
}

func TestCoreAreMembersCompatible(t *testing.T) {
	tests := []struct {
		a, b       Type
		compatible bool
	}{
		{&Struct{Name: "a"}, &Struct{Name: "b"}, true},
		{&Union{Name: "a"}, &Union{Name: "b"}, true},
		{&Union{Name: "a"}, &Struct{Name: "b"}, true},
		{&Enum{Name: "a"}, &Enum{Name: "b"}, false},
		{&Enum{Name: "a"}, &Enum{Name: "a___foo"}, true},
		{&Enum{Name: "a"}, &Enum{Name: ""}, true},
		{&Fwd{Name: "a"}, &Fwd{Name: "b"}, false},
		{&Fwd{Name: "a"}, &Fwd{Name: "a___foo"}, true},
		{&Fwd{Name: "a"}, &Fwd{Name: ""}, true},
		{&Int{Name: "a", Size: 2}, &Int{Name: "b", Size: 4}, true},
		{&Int{Offset: 1}, &Int{}, false},
		{&Pointer{Target: &Void{}}, &Pointer{Target: &Void{}}, true},
		{&Pointer{Target: &Void{}}, &Void{}, false},
		{&Array{Type: &Int{}}, &Array{Type: &Int{}}, true},
		{&Array{Type: &Int{}}, &Array{Type: &Void{}}, false},
		{&Typedef{Name: "a", Type: &Int{}}, &Int{}, true},
		{&Typedef{Name: "a", Type: &Int{}}, &Void{}, false},
		{&Const{Type: &Int{}}, &Int{}, true},
		{&Const{Type: &Int{}}, &Void{}, false},
		{&Volatile{Type: &Int{}}, &Int{}, true},
		{&Volatile{Type: &Int{}}, &Void{}, false},
		{&Restrict{Type: &Int{}}, &Int{}, true},
		{&Restrict{Type: &Int{}}, &Void{}, false},
	}

	for _, test := range tests {
		compatible, err := coreAreMembersCompatible(test.a, test.b)
		if err != nil {
			t.Errorf("Can't compare types: %s\na = %#v\nb = %#v", err, test.a, test.b)
			continue
		}

		if compatible != test.compatible {
			if test.compatible {
				t.Errorf("Expected types to be compatible:\na = %#v\nb = %#v", test.a, test.b)
			} else {
				t.Errorf("Expected types to be incompatible:\na = %#v\nb = %#v", test.a, test.b)
			}
			continue
		}

		compatibleReverse, err := coreAreMembersCompatible(test.b, test.a)
		if err != nil {
			t.Errorf("Can't compare reversed types: %s\na = %#v\nb = %#v", err, test.a, test.b)
			continue
		}
		if compatibleReverse != compatible {
			t.Errorf("Expected the reverse comparison to be %v as well:\na = %#v\nb = %#v", compatible, test.a, test.b)
		}
	}

	for _, invalid := range []Type{&Void{}, &FuncProto{}, &Var{}, &Datasec{}} {
		_, err := coreAreMembersCompatible(invalid, invalid)
		if err == nil {
			t.Errorf("Expected an error for %T", invalid)
		}
	}
}

func TestCoreAccessor(t *testing.T) {
	for _, valid := range []string{
		"0",
		"1:0",
		"1:0:3:34:10:1",
	} {
		_, err := parseCoreAccessor(valid)
		if err != nil {
			t.Errorf("Parse %q: %s", valid, err)
		}
	}

	for _, invalid := range []string{
		"",
		"-1",
		":",
		"0:",
		":12",
		"4294967296",
	} {
		_, err := parseCoreAccessor(invalid)
		if err == nil {
			t.Errorf("Accepted invalid accessor %q", invalid)
		}
	}
}

func TestCoreRelocation(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/*.elf"), func(t *testing.T, file string) {
		rd, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		defer rd.Close()

		spec, err := LoadSpecFromReader(rd)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal(err)
		}

		errs := map[string]error{
			"ambiguous":         errAmbiguousRelocation,
			"ambiguous_flavour": errAmbiguousRelocation,
		}

		for section := range spec.funcInfos {
			name := strings.TrimPrefix(section, "socket_filter/")
			t.Run(name, func(t *testing.T) {
				prog, err := spec.Program(section, 1)
				if err != nil {
					t.Fatal("Retrieve program:", err)
				}

				relos, err := ProgramRelocations(prog, spec)
				testutils.SkipIfNotSupported(t, err)
				if want := errs[name]; want != nil {
					if !errors.Is(err, want) {
						t.Fatal("Expected", want, "got", err)
					}
					return
				}

				if err != nil {
					t.Fatal("Can't relocate against itself:", err)
				}

				for i, relo := range relos {
					if relo.Current != relo.New {
						// Since we're relocating against ourselves both values
						// should match.
						t.Errorf("#%d: current %v doesn't match new %d", i, relo.Current, relo.New)
					}
				}
			})
		}
	})
}
