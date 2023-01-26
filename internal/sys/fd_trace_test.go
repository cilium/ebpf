package sys

import (
	"testing"
)

func TestLeakTracersPackage(t *testing.T) {
	Create = Exiter

	if !tracing() {
		t.Fatal("expected package to have active fd tracers")
	}

	Create = nil

	if tracing() {
		t.Fatal("expected package to not have active fd tracers")
	}
}
