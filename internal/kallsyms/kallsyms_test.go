package kallsyms

import (
	"bytes"
	"os"
	"testing"

	"github.com/go-quicktest/qt"
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
A0000000000000EA t writenote`)

func TestParseSyms(t *testing.T) {
	r := newReader(bytes.NewReader(syms))
	i := 0
	for ; r.Line(); i++ {
		s, err, skip := parseSymbol(r, nil)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsFalse(skip))
		qt.Assert(t, qt.Not(qt.Equals(s.addr, 0)))
		qt.Assert(t, qt.Not(qt.Equals(s.name, "")))
	}
	qt.Assert(t, qt.IsNil(r.Err()))
	qt.Assert(t, qt.Equals(i, 13))
}

func TestParseProcKallsyms(t *testing.T) {
	f, err := os.Open("/proc/kallsyms")
	qt.Assert(t, qt.IsNil(err))
	defer f.Close()

	// Read up to 50k symbols from kallsyms to avoid a slow test.
	r := newReader(f)
	for i := 0; r.Line() && i < 50_000; i++ {
		s, err, skip := parseSymbol(r, nil)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsFalse(skip))
		qt.Assert(t, qt.Not(qt.Equals(s.name, "")))
	}
	qt.Assert(t, qt.IsNil(r.Err()))
}

func TestAssignModulesCaching(t *testing.T) {
	qt.Assert(t, qt.IsNil(AssignModules(
		map[string]string{
			"bpf_perf_event_output": "",
			"foo":                   "",
		},
	)))

	// Can't assume any kernel modules are loaded, but this symbol should at least
	// exist in the kernel. There is no semantic difference between a missing
	// symbol and a symbol that doesn't belong to a module.
	v, ok := symModules.Load("bpf_perf_event_output")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(v, ""))

	v, ok = symModules.Load("foo")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(v, ""))
}

func TestAssignModules(t *testing.T) {
	mods := map[string]string{
		"hid_generic_probe": "",
		"nft_counter_seq":   "",
		"tcp_connect":       "",
		"foo":               "",
	}
	qt.Assert(t, qt.IsNil(assignModules(bytes.NewBuffer(syms), mods)))
	qt.Assert(t, qt.DeepEquals(mods, map[string]string{
		"hid_generic_probe": "hid_generic",
		"nft_counter_seq":   "", // wrong symbol type
		"tcp_connect":       "",
		"foo":               "",
	}))

	qt.Assert(t, qt.ErrorIs(assignModules(bytes.NewBuffer(syms),
		map[string]string{"writenote": ""}), errAmbiguousKsym))
}

func TestAssignAddressesCaching(t *testing.T) {
	qt.Assert(t, qt.IsNil(AssignAddresses(
		map[string]uint64{
			"bpf_perf_event_output": 0,
			"foo":                   0,
		},
	)))

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

func BenchmarkSymbolKmods(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f, err := os.Open("/proc/kallsyms")
		qt.Assert(b, qt.IsNil(err))
		want := map[string]string{
			"bpf_trace_vprintk":     "",
			"bpf_send_signal":       "",
			"bpf_event_notify":      "",
			"bpf_trace_printk":      "",
			"bpf_perf_event_output": "",
		}
		b.StartTimer()

		if err := assignModules(f, want); err != nil {
			b.Fatal(err)
		}

		f.Close()
	}
}

// Benchmark getting 5 kernel symbols from /proc/kallsyms.
func BenchmarkAssignAddresses(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f, err := os.Open("/proc/kallsyms")
		qt.Assert(b, qt.IsNil(err))
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

		f.Close()
	}
}
