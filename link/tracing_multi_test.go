//go:build !windows

package link

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/internal/kfunc"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestTracingMulti(t *testing.T) {
	testutils.SkipIfNotSupported(t, features.HaveBPFLinkTracingMulti())

	ids := mustKernelFuncBTFIDs(t, []string{
		"bpf_fentry_test1",
		"bpf_fentry_test2",
	})

	for _, attachType := range []ebpf.AttachType{
		ebpf.AttachTraceFEntryMulti,
		ebpf.AttachTraceFExitMulti,
		ebpf.AttachTraceFSessionMulti,
	} {
		t.Run(attachType.String(), func(t *testing.T) {
			prog := mustLoadProgram(t, ebpf.Tracing, attachType, "")

			link, err := AttachTracingMulti(TracingMultiOptions{
				Program:    prog,
				AttachType: attachType,
				BTFIDs:     ids,
				Cookies:    []uint64{1, 2},
			})
			if err != nil {
				t.Fatal("Can't attach tracing_multi:", err)
			}
			defer link.Close()

			t.Run("info", func(t *testing.T) {
				info, err := link.Info()
				testutils.SkipIfNotSupported(t, err)
				if err != nil {
					t.Fatal("Can't get tracing_multi link info:", err)
				}
				if info.Type != TracingMultiType {
					t.Fatalf("expected link type %v, got %v", TracingMultiType, info.Type)
				}
				tracingMulti := info.TracingMulti()
				if tracingMulti == nil {
					t.Fatal("missing tracing_multi info")
				}
				if tracingMulti.AttachType != sys.AttachType(attachType) {
					t.Fatalf("expected attach type %s, got %s", attachType, tracingMulti.AttachType)
				}
				targets, ok := tracingMulti.Targets()
				if !ok {
					t.Fatal("tracing_multi targets unavailable")
				}
				if len(targets) != len(ids) || tracingMulti.Count != uint32(len(ids)) {
					t.Fatalf("expected %d targets, got %d (count %d)", len(ids), len(targets), tracingMulti.Count)
				}
				wantCookies := map[btf.TypeID]uint64{ids[0]: 1, ids[1]: 2}
				for _, target := range targets {
					if want, ok := wantCookies[target.BtfID]; !ok || target.Cookie != want {
						t.Fatalf("unexpected tracing_multi target: %+v", target)
					}
					delete(wantCookies, target.BtfID)
				}
				if len(wantCookies) != 0 {
					t.Fatalf("missing tracing_multi targets: %v", wantCookies)
				}
			})

			testLink(t, link, prog)
		})
	}
}

func TestTracingMultiInput(t *testing.T) {
	_, err := AttachTracingMulti(TracingMultiOptions{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for nil program, got: %v", err)
	}

	testutils.SkipIfNotSupported(t, features.HaveBPFLinkTracingMulti())

	wrongType := mustLoadProgram(t, ebpf.SocketFilter, ebpf.AttachNone, "")
	_, err = AttachTracingMulti(TracingMultiOptions{
		Program:    wrongType,
		AttachType: ebpf.AttachTraceFEntryMulti,
		BTFIDs:     []btf.TypeID{1},
	})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for wrong program type, got: %v", err)
	}

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceFEntryMulti, "")
	tests := []struct {
		name string
		opts TracingMultiOptions
	}{
		{
			name: "missing BTF IDs",
			opts: TracingMultiOptions{
				Program:    prog,
				AttachType: ebpf.AttachTraceFEntryMulti,
			},
		},
		{
			name: "invalid attach type",
			opts: TracingMultiOptions{
				Program:    prog,
				AttachType: ebpf.AttachTraceFEntry,
				BTFIDs:     []btf.TypeID{1},
			},
		},
		{
			name: "cookie count mismatch",
			opts: TracingMultiOptions{
				Program:    prog,
				AttachType: ebpf.AttachTraceFEntryMulti,
				BTFIDs:     []btf.TypeID{1},
				Cookies:    []uint64{1, 2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := AttachTracingMulti(tt.opts)
			if !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got: %v", err)
			}
		})
	}

	closed := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceFEntryMulti, "")
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = AttachTracingMulti(TracingMultiOptions{
		Program:    closed,
		AttachType: ebpf.AttachTraceFEntryMulti,
		BTFIDs:     []btf.TypeID{1},
	})
	if !errors.Is(err, sys.ErrClosedFd) {
		t.Fatalf("expected ErrClosedFd, got: %v", err)
	}
}

func mustKernelFuncBTFIDs(tb testing.TB, names []string) []btf.TypeID {
	tb.Helper()

	ids, err := kfunc.IDs(names, true)
	testutils.SkipIfNotSupported(tb, err)
	if errors.Is(err, btf.ErrNotFound) {
		tb.Skip("Skipping since tracing_multi test BTF IDs are unavailable")
	}
	if err != nil {
		tb.Fatal("Can't resolve BTF IDs:", err)
	}
	return ids
}
