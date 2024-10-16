package kallsyms

import (
	"bytes"
	"os"
	"testing"

	"github.com/go-quicktest/qt"
)

var kallsyms = []byte(`0000000000000000 t hid_generic_probe	[hid_generic]
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

func TestKernelModule(t *testing.T) {
	krdr := bytes.NewBuffer(kallsyms)
	kmods, err := loadKernelModuleMapping(krdr)
	qt.Assert(t, qt.IsNil(err))

	// present and in module
	kmod := kmods["hid_generic_probe"]
	if kmod != "hid_generic" {
		t.Errorf("expected %q got %q", "hid_generic", kmod)
	}

	// present but not kernel module
	kmod = kmods["tcp_connect"]
	if kmod != "" {
		t.Errorf("expected %q got %q", "", kmod)
	}

	qt.Assert(t, qt.Equals(kmods["nft_counter_seq"], ""))
}

func TestLoadSymbolAddresses(t *testing.T) {
	b := bytes.NewBuffer(kallsyms)
	ksyms := map[string]uint64{
		"hid_generic_probe": 0,
		"tcp_connect":       0,
		"bootconfig_found":  0,
	}
	qt.Assert(t, qt.IsNil(loadSymbolAddresses(b, ksyms)))

	qt.Assert(t, qt.Equals(ksyms["hid_generic_probe"], 0))
	qt.Assert(t, qt.Equals(ksyms["tcp_connect"], 0xA0))
	qt.Assert(t, qt.Equals(ksyms["bootconfig_found"], 0xA0000000000000BA))

	b = bytes.NewBuffer(kallsyms)
	ksyms = map[string]uint64{
		"hid_generic_probe": 0,
		"writenote":         0,
	}
	err := loadSymbolAddresses(b, ksyms)
	qt.Assert(t, qt.ErrorIs(err, errKsymIsAmbiguous))
}

func BenchmarkSymbolKmods(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f, err := os.Open("/proc/kallsyms")
		qt.Assert(b, qt.IsNil(err))
		b.StartTimer()

		if _, err := loadKernelModuleMapping(f); err != nil {
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

		if err := loadSymbolAddresses(f, want); err != nil {
			b.Fatal(err)
		}

		f.Close()
	}
}
