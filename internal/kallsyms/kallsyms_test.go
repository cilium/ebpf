package kallsyms

import (
	"bytes"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestKernelModule(t *testing.T) {
	kallsyms := []byte(`0000000000000000 t hid_generic_probe	[hid_generic]
0000000000000000 T tcp_connect
0000000000000000 B empty_zero_page
0000000000000000 D kimage_vaddr
0000000000000000 R __start_pci_fixups_early
0000000000000000 V hv_root_partition
0000000000000000 W calibrate_delay_is_known
0000000000000000 a nft_counter_seq	[nft_counter]
0000000000000000 b bootconfig_found
0000000000000000 d __func__.10
0000000000000000 r __ksymtab_LZ4_decompress_fast`)
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
