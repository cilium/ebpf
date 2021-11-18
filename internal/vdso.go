package internal

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

const (
	_AT_NULL         = 0
	_AT_SYSINFO_EHDR = 33
)

// vdsoVersion returns the LINUX_VERSION_CODE embedded in the vDSO library linked to the current process.
func vdsoVersion() (uint32, error) {
	// read data from the auxiliary vector, which is normally passed directly to the process.
	// Go does not expose that data, so we must read it from procfs.
	// https://man7.org/linux/man-pages/man3/getauxval.3.html
	av, err := os.Open("/proc/self/auxv")
	if err != nil {
		return 0, fmt.Errorf("open auxv: %w", err)
	}
	defer av.Close()

	vdsoAddr, err := vdsoMemoryAddress(av)
	if err != nil {
		return 0, fmt.Errorf("vdso elf header: %w", err)
	}

	// use /proc/self/mem rather than unsafe.Pointer tricks
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return 0, fmt.Errorf("open mem: %w", err)
	}
	defer mem.Close()

	// open ELF at provided memory address, as offset into /proc/self/mem
	r := io.NewSectionReader(mem, int64(vdsoAddr), math.MaxInt64)
	return linuxVersionCode(r)
}

// vdsoMemoryAddress returns the memory address of the vDSO library linked to the current process.
func vdsoMemoryAddress(r io.Reader) (uint64, error) {
	abuf, err := io.ReadAll(r)
	if err != nil {
		return 0, fmt.Errorf("readall auxv: %w", err)
	}

	br := bytes.NewReader(abuf)
	// ensure we only read the exact number of uint64s
	buf := make([]uint64, len(abuf)/8)
	err = binary.Read(br, NativeEndian, &buf)
	if err != nil {
		return 0, fmt.Errorf("binary read auxv: %w", err)
	}

	// loop through all the type+value pairs until we find `AT_SYSINFO_EHDR`, described as:
	// The address of a page containing the virtual Dynamic
	// Shared Object (vDSO) that the kernel creates in order to
	// provide fast implementations of certain system calls.
	for i := 0; i < len(buf)-1 && buf[i] != _AT_NULL; i += 2 {
		tag, val := buf[i], buf[i+1]
		switch tag {
		case _AT_SYSINFO_EHDR:
			if val == 0 {
				return 0, fmt.Errorf("invalid address")
			}
			return val, nil
		}
	}
	return 0, fmt.Errorf("not found")
}

// format described at https://www.man7.org/linux/man-pages/man5/elf.5.html in section 'Notes (Nhdr)'
type elfNote struct {
	NameSize int32
	DescSize int32
	Type     int32
}

// linuxVersionCode returns the LINUX_VERSION_CODE embedded in the ELF notes section
// of the binary provided by the reader.
func linuxVersionCode(r io.ReaderAt) (uint32, error) {
	hdr, err := NewSafeELFFile(r)
	if err != nil {
		return 0, fmt.Errorf("new elf: %w", err)
	}

	sec := hdr.SectionByType(elf.SHT_NOTE)
	if sec == nil {
		return 0, fmt.Errorf("note elf section not found")
	}

	sr := sec.Open()
	// keep reading notes until we find one named `Linux` with 4 bytes
	for {
		n := elfNote{}
		if err := binary.Read(sr, hdr.ByteOrder, &n); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return 0, fmt.Errorf("read note: %w", err)
		}
		var name string
		if n.NameSize > 0 {
			// make a 4-byte aligned read, but trim excess bytes and null terminating bytes to obtain name
			nameData := make([]byte, Align(int(n.NameSize), 4))
			err := binary.Read(sr, hdr.ByteOrder, &nameData)
			if err != nil {
				return 0, fmt.Errorf("read note name: %w", err)
			}
			name = strings.Trim(string(nameData[:n.NameSize]), "\x00")
		}
		if n.DescSize > 0 {
			desc := make([]byte, Align(int(n.DescSize), 4))
			err := binary.Read(sr, hdr.ByteOrder, &desc)
			if err != nil {
				return 0, fmt.Errorf("read note desc: %w", err)
			}
			if name == "Linux" && n.DescSize == 4 && n.Type == 0 {
				// LINUX_VERSION_CODE is a uint32 value
				return hdr.ByteOrder.Uint32(desc[:n.DescSize]), nil
			}
		}
	}
	return 0, fmt.Errorf("linux version note not found")
}
