package btf

import "testing"

func TestSizeof(t *testing.T) {
	testcases := []struct {
		size int
		typ  Type
	}{
		{1, &Int{Size: 1}},
		{4, &Enum{}},
		{0, &Array{Type: &Pointer{Void{}}, Nelems: 0}},
		{12, &Array{Type: &Enum{}, Nelems: 3}},
	}

	for _, tc := range testcases {
		t.Run(tc.typ.String(), func(t *testing.T) {
			have := Sizeof(tc.typ)
			if have != tc.size {
				t.Errorf("Expected size %d, got %d", tc.size, have)
			}
		})
	}
}
