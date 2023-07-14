package internal

import (
	"fmt"
	"go/importer"
	"strings"
	"testing"
	"unicode"
)

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
			if want, got := tt.r, IsPow(tt.n); want != got {
				t.Errorf("unexpected result for n %d; want: %v, got: %v", tt.n, want, got)
			}
		})
	}
}

var (
	// integerConstraintTests holds compile test cases exercising the Integer constraint for each of the keyed int types.
	// testcases for new predeclared integer types should be added in init() functions in build-constrained files for appropriate go versions.
	integerConstraintTests = map[string]func(){
		"int":     func() { Align(int(1), int(1)) },
		"int16":   func() { Align(int16(1), int16(1)) },
		"int32":   func() { Align(int32(1), int32(1)) },
		"int64":   func() { Align(int64(1), int64(1)) },
		"int8":    func() { Align(int8(1), int8(1)) },
		"uint":    func() { Align(uint(1), uint(1)) },
		"uint16":  func() { Align(uint16(1), uint16(1)) },
		"uint32":  func() { Align(uint32(1), uint32(1)) },
		"uint64":  func() { Align(uint64(1), uint64(1)) },
		"uint8":   func() { Align(uint8(1), uint8(1)) },
		"uintptr": func() { Align(uintptr(1), uintptr(1)) },
	}

	// integerConstraintFalsePositives holds symbols in the reflect package containing 'int' which are not actually integer types.
	integerConstraintFalsePositives = map[string]struct{}{
		"interface":     struct{}{},
		"unsafepointer": struct{}{},
		"pointer":       struct{}{},
		"pointerto":     struct{}{},
	}
)

func TestIntegerConstraint(t *testing.T) {
	pkg, err := importer.Default().Import("reflect")
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range pkg.Scope().Names() {
		if !unicode.IsUpper(rune(name[0])) {
			continue
		}
		lowerName := strings.ToLower(name)
		if !strings.Contains(lowerName, "int") {
			continue
		}
		if _, falsePositive := integerConstraintFalsePositives[lowerName]; falsePositive {
			continue
		}
		integerConstraintTest, ok := integerConstraintTests[lowerName]
		if !ok {
			t.Errorf("Unexpected symbol reflect.%s containing 'int' as a substring.", name)
			t.Errorf("If this is a false positive 'int' substring match, add it to the falsePositives map above.")
			t.Errorf("If this is a new predeclared integer type, add a test case for it to integerConstraintTests in an init() block in a file for appropriate go versions.")
			continue
		}
		integerConstraintTest()
	}
}
