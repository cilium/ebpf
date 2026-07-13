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
	}, 2)

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

func mustKernelFuncBTFIDs(tb testing.TB, names []string, count int) []btf.TypeID {
	tb.Helper()

	ids, err := kfunc.IDs(names, count)
	testutils.SkipIfNotSupported(tb, err)
	if errors.Is(err, btf.ErrNotFound) {
		tb.Skipf("Skipping since fewer than %d tracing_multi test BTF IDs are available", count)
	}
	if err != nil {
		tb.Fatal("Can't resolve BTF IDs:", err)
	}
	return ids
}
