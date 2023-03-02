package btf

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestDatasecResolveWorkaround(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.2", "BTF_KIND_DATASEC")

	i := &Int{Size: 1}

	for _, typ := range []Type{
		&Typedef{"foo", i},
		&Volatile{i},
		&Const{i},
		&Restrict{i},
		&typeTag{i, "foo"},
	} {
		t.Run(fmt.Sprint(typ), func(t *testing.T) {
			if _, ok := typ.(*typeTag); ok {
				testutils.SkipOnOldKernel(t, "5.17", "BTF_KIND_TYPE_TAG")
			}

			ds := &Datasec{
				Name: "a",
				Size: 2,
				Vars: []VarSecinfo{
					{
						Size:   1,
						Offset: 0,
						// struct, union, pointer, array will trigger the bug.
						Type: &Var{Name: "a", Type: &Pointer{i}},
					},
					{
						Size:   1,
						Offset: 1,
						Type: &Var{
							Name: "b",
							Type: typ,
						},
					},
				},
			}

			spec := NewSpec()
			if err := datasecResolveWorkaround(spec, ds); err != nil {
				t.Fatal(err)
			}

			_, err := spec.Add(ds)
			if err != nil {
				t.Fatal(err)
			}

			h, err := NewHandle(spec)
			var ve *internal.VerifierError
			if errors.As(err, &ve) {
				t.Fatalf("%+v\n", ve)
			}
			if err != nil {
				t.Fatal(err)
			}
			h.Close()
		})
	}
}
