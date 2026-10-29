package internal

import (
	"fmt"
	"testing"

	"github.com/go-quicktest/qt"
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

func TestBetween(t *testing.T) {
	tests := []struct {
		val, a, b, r int
	}{
		{0, 1, 2, 1},
		{1, 1, 2, 1},
		{2, 1, 2, 2},
		{3, 1, 2, 2},
		{4, 10, 5, 5},
		{11, 10, 5, 10},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d between %d and %d", tt.val, tt.a, tt.b), func(t *testing.T) {
			qt.Assert(t, qt.Equals(Between(tt.val, tt.a, tt.b), tt.r))
		})
	}
}
