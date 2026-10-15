package kfunc

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestIDsOnePerName(t *testing.T) {
	spec := testSpec(t)

	got, err := ids(spec, []string{"single"}, true)
	if err != nil {
		t.Fatal("Resolve single function:", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one ID, got %d", len(got))
	}

	for _, names := range [][]string{{"missing"}, {"single", "missing"}} {
		if _, err := ids(spec, names, true); !errors.Is(err, btf.ErrNotFound) {
			t.Errorf("IDs(%v): expected ErrNotFound, got %v", names, err)
		}
	}

	if _, err := ids(spec, []string{"duplicate"}, true); !errors.Is(err, btf.ErrMultipleMatches) {
		t.Errorf("expected ErrMultipleMatches, got %v", err)
	}
}

func TestIDsAllMatches(t *testing.T) {
	spec := testSpec(t)

	got, err := ids(spec, []string{"duplicate", "missing", "single", "duplicate"}, false)
	if err != nil {
		t.Fatal("Resolve all matching functions:", err)
	}

	// The duplicate name has two functions. The repeated input name must not
	// duplicate their IDs, and the non-function with the same name is ignored.
	if len(got) != 3 {
		t.Fatalf("expected three unique function IDs, got %d", len(got))
	}

	if _, err := ids(spec, []string{"missing", "type_only"}, false); !errors.Is(err, btf.ErrNotFound) {
		t.Errorf("expected ErrNotFound when no functions match, got %v", err)
	}
}

func testSpec(t *testing.T) *btf.Spec {
	t.Helper()

	intType := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	types := []btf.Type{
		&btf.Func{
			Name:    "single",
			Type:    &btf.FuncProto{Return: intType},
			Linkage: btf.GlobalFunc,
		},
		&btf.Func{
			Name:    "duplicate",
			Type:    &btf.FuncProto{Return: intType},
			Linkage: btf.GlobalFunc,
		},
		&btf.Func{
			Name:    "duplicate",
			Type:    &btf.FuncProto{Return: &btf.Void{}},
			Linkage: btf.GlobalFunc,
		},
		&btf.Int{Name: "type_only", Size: 4, Encoding: btf.Signed},
		&btf.Int{Name: "duplicate", Size: 4, Encoding: btf.Signed},
	}

	builder, err := btf.NewBuilder(types, nil)
	if err != nil {
		t.Fatal("Create BTF builder:", err)
	}
	spec, err := builder.Spec()
	if err != nil {
		t.Fatal("Create BTF spec:", err)
	}
	return spec
}
