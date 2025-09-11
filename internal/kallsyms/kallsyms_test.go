package kallsyms

import (
	"bytes"
	"os"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/testutils"
)

var syms = []byte(`0000000000000001 t hid_generic_probe	[hid_generic]
00000000000000EA t writenote
00000000000000A0 T tcp_connect
00000000000000B0 B empty_zero_page
00000000000000C0 D kimage_vaddr
00000000000000D0 R __start_pci_fixups_early
00000000000000E0 V hv_root_partition
00000000000000F0 W calibrate_delay_is_known
A0000000000000AA a nft_counter_seq	[nft_counter]
A0000000000000BA b bootconfig_found
A0000000000000CA d __func__.10
A0000000000000DA r __ksymtab_LZ4_decompress_fast
A0000000000000EA t writenote
A0000000000000FA T bench_sym	[bench_mod]
A0000000000000FF t __kstrtab_功能	[mod]`)

func TestParseSyms(t *testing.T) {
	r := newReader(bytes.NewReader(syms))
	i := 0
	for ; r.Line(); i++ {
		s, err, skip := parseSymbol(r, nil)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsFalse(skip))
		qt.Assert(t, qt.Not(qt.Equals(s.addr, 0)))
		qt.Assert(t, qt.Not(qt.Equals(s.name, []byte(""))))
	}
	qt.Assert(t, qt.IsNil(r.Err()))
	qt.Assert(t, qt.Equals(i, 15))
}

func TestParseProcKallsyms(t *testing.T) {
	// Read up to 50k symbols from kallsyms to avoid a slow test.
	r := newReader(mustOpenProcKallsyms(t))
	for i := 0; r.Line() && i < 50_000; i++ {
		s, err, skip := parseSymbol(r, nil)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsFalse(skip))
		qt.Assert(t, qt.Not(qt.Equals(s.name, []byte(""))))
	}
	qt.Assert(t, qt.IsNil(r.Err()))
}

func TestAssignAddressesCaching(t *testing.T) {
	err := AssignAddresses(
		map[string]uint64{
			"bpf_perf_event_output": 0,
			"foo":                   0,
		},
	)
	testutils.SkipIfNotSupportedOnOS(t, err)
	qt.Assert(t, qt.IsNil(err))

	v, ok := symAddrs.Load("bpf_perf_event_output")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Not(qt.Equals(v, 0)))

	v, ok = symAddrs.Load("foo")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(v, 0))
}

func TestAssignAddresses(t *testing.T) {
	b := bytes.NewBuffer(syms)
	ksyms := map[string]uint64{
		"hid_generic_probe": 0,
		"tcp_connect":       0,
		"bootconfig_found":  0,
	}
	qt.Assert(t, qt.IsNil(assignAddresses(b, ksyms)))

	qt.Assert(t, qt.Equals(ksyms["hid_generic_probe"], 0x1))
	qt.Assert(t, qt.Equals(ksyms["tcp_connect"], 0xA0))
	qt.Assert(t, qt.Equals(ksyms["bootconfig_found"], 0xA0000000000000BA))

	b = bytes.NewBuffer(syms)
	ksyms = map[string]uint64{
		"hid_generic_probe": 0,
		"writenote":         0,
	}
	qt.Assert(t, qt.ErrorIs(assignAddresses(b, ksyms), errAmbiguousKsym))
}

func BenchmarkAssignAddresses(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		f := bytes.NewBuffer(syms)
		want := map[string]uint64{"bench_sym": 0}
		b.StartTimer()

		if err := assignAddresses(f, want); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark getting 5 kernel symbols from /proc/kallsyms.
func BenchmarkAssignAddressesKallsyms(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		f := mustOpenProcKallsyms(b)
		want := map[string]uint64{
			"bpf_trace_vprintk":     0,
			"bpf_send_signal":       0,
			"bpf_event_notify":      0,
			"bpf_trace_printk":      0,
			"bpf_perf_event_output": 0,
		}
		b.StartTimer()

		if err := assignAddresses(f, want); err != nil {
			b.Fatal(err)
		}
	}
}

func mustOpenProcKallsyms(tb testing.TB) *os.File {
	tb.Helper()

	if !platform.IsLinux {
		tb.Skip("/proc/kallsyms is a Linux concept")
	}

	f, err := os.Open("/proc/kallsyms")
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() { f.Close() })
	return f
}
