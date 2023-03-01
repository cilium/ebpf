package btf

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf/internal"
)

func TestDatasecResolveWorkaround(t *testing.T) {
	i := &Int{Size: 1}

	for _, typ := range []Type{
		&Typedef{"foo", i},
		&Volatile{i},
		&Const{i},
		&Restrict{i},
		&typeTag{i, "foo"},
	} {
		t.Run(fmt.Sprint(typ), func(t *testing.T) {
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
