package link

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestStructOps(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.12", "bpf_testmod_ops")

	coll, err := mustStructOpsFixtures(t)
	if errors.Is(err, ErrNotSupported) {
		t.Skipf("bpf_testmod_ops: %s", err)
	}
	if err != nil {
		t.Fatal(err)
	}

	m := coll.Maps["testmod_ops"]
	if m == nil {
		t.Fatal("map: testmod_ops not found")
	}

	p := coll.Programs["test_1"]
	if m == nil {
		t.Fatal("prog: test_1 not found")
	}

	l, err := AttachStructOps(m)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Close the program and map on test teardown.
	t.Cleanup(func() {
		m.Close()
		p.Close()
	})
}
