package btf

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"io/ioutil"
	"os"
	"testing"
)

func TestParseVmlinux(t *testing.T) {
	fh, err := os.Open("testdata/vmlinux-btf.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	rd, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := ioutil.ReadAll(rd)
	if err != nil {
		t.Fatal(err)
	}

	_, err = LoadSpecFromReader(bytes.NewReader(buf), nil, binary.LittleEndian)
	if err != nil {
		t.Error("Can't load BTF:", err)
	}
}

func TestLoadSpecFromElf(t *testing.T) {
	fh, err := os.Open("../testdata/loader-clang-8.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	ef, err := elf.NewFile(fh)
	if err != nil {
		t.Fatal(ef)
	}
	defer ef.Close()

	spec, err := LoadSpecFromELF(ef)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}

	if spec == nil {
		t.Error("No BTF found in ELF")
	}

	if sec, err := spec.Section("xdp", 1); err != nil {
		t.Error("Can't get BTF for the xdp section:", err)
	} else if sec == nil {
		t.Error("Missing BTF for the xdp section")
	}

	if sec, err := spec.Section("socket", 1); err != nil {
		t.Error("Can't get BTF for the socket section:", err)
	} else if sec == nil {
		t.Error("Missing BTF for the socket section")
	}

	if !Supported() {
		return
	}

	btf, err := New(spec)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}
	defer btf.Close()
}
