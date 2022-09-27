package unix

import (
	"testing"
)

func TestSigset(t *testing.T) {
	// Type-infer a sigset word. This is a typed uint of 32 or 64 bits depending
	// on the target architecture, so we can't use an untyped uint.
	zero := Sigset_t{}.Val[0]
	words := len(Sigset_t{}.Val)

	var want, got Sigset_t
	// Flip the first bit of the first word.
	if err := SigsetAdd(&got, 1); err != nil {
		t.Fatal(err)
	}
	want.Val[0] = 1
	if want != got {
		t.Fatalf("expected first word to be 0x%x, got: 0x%x", want, got)
	}

	// And the last bit of the last word.
	if err := SigsetAdd(&got, Signal(setBits)); err != nil {
		t.Fatal(err)
	}
	want.Val[words-1] = ^(^zero >> 1)
	if want != got {
		t.Fatalf("expected last word to be 0x%x, got: 0x%x", want, got)
	}

	if err := SigsetAdd(&got, Signal(setBits+1)); err == nil {
		t.Fatal("expected out-of-bounds add to be rejected")
	}
	if err := SigsetAdd(&got, -1); err == nil {
		t.Fatal("expected negative signal to be rejected")
	}
}
