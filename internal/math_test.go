package internal

import (
	"fmt"
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
