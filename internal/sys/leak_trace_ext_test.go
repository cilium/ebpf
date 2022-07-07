package sys_test

import (
	"testing"

	"github.com/cilium/ebpf/internal/sys"
)

func TestLeakTracersPackage(t *testing.T) {
	tracer := sys.NewLeakTracer()

	if !sys.HaveLeakTracers() {
		t.Fatal("expected package sys to have active leak tracers")
	}

	tracer.Close()

	if sys.HaveLeakTracers() {
		t.Fatal("expected package sys to not have active leak tracers")
	}
}
