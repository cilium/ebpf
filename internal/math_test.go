package internal

import (
	"fmt"
	"go/importer"
	"regexp"
	"slices"
	"strings"
	"testing"
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

func TestIntegerConstraint(t *testing.T) {
	rgx := regexp.MustCompile(`^(u)?int([0-9]*|ptr)?$`)

	pkg, err := importer.Default().Import("reflect")
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range pkg.Scope().Names() {
		name = strings.ToLower(name)
		if !rgx.MatchString(name) {
			continue
		}

		if !slices.Contains(integers, name) {
			t.Errorf("Go type %s is not in the list of known integer types", name)
		}
	}
}
