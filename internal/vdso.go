package internal

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"unsafe"
)

const (
	_AT_NULL         = 0
	_AT_SYSINFO_EHDR = 33
)

func vdsoVersion() (uint32, error) {
	eh, err := vdsoELFHeader()
	if err != nil {
		return 0, fmt.Errorf("vdso elf header: %w", err)
	}
	return linuxVersionCode(eh)
}

func vdsoELFHeader() (*elf.File, error) {
	av, err := os.Open("/proc/self/auxv")
	if err != nil {
		return nil, fmt.Errorf("open auxv: %w", err)
	}
	defer av.Close()

	abuf, err := ioutil.ReadAll(av)
	if err != nil {
		return nil, fmt.Errorf("readall auxv: %w", err)
	}

	br := bytes.NewReader(abuf)
	buf := make([]uint64, len(abuf)/8)
	err = binary.Read(br, NativeEndian, &buf)
	if err != nil {
		return nil, fmt.Errorf("binary read auxv: %w", err)
	}

	for i := 0; i < len(buf)-1 && buf[i] != _AT_NULL; i += 2 {
		tag, val := buf[i], buf[i+1]
		switch tag {
		case _AT_SYSINFO_EHDR:
			if val == 0 {
				continue
			}
			return elf.NewFile(newUnsafeReader(unsafe.Pointer(uintptr(val))))
		}
	}
	return nil, fmt.Errorf("not found")
}

type note struct {
	NameSize int32
	DescSize int32
	Type     int32
}

type unsafeReader struct {
	base unsafe.Pointer
	off  int64
}

func newUnsafeReader(base unsafe.Pointer) io.ReaderAt {
	return &unsafeReader{base, 0}
}

func (r *unsafeReader) offsetPtr(off int64) unsafe.Pointer {
	return unsafe.Pointer(uintptr(r.base) + uintptr(off))
}

func (r *unsafeReader) ReadAt(p []byte, off int64) (n int, err error) {
	sz := len(p)

	var b []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	hdr.Data = uintptr(r.offsetPtr(off))
	hdr.Len = sz
	hdr.Cap = sz
	return copy(p, b), nil
}

func linuxVersionCode(hdr *elf.File) (uint32, error) {
	sec := hdr.SectionByType(elf.SHT_NOTE)
	if sec == nil {
		return 0, fmt.Errorf("note elf section not found")
	}

	sr := sec.Open()
	for {
		n := note{}
		if err := binary.Read(sr, hdr.ByteOrder, &n); err != nil {
			if err == io.EOF {
				break
			}
			return 0, fmt.Errorf("read note: %w", err)
		}
		var name string
		if n.NameSize > 0 {
			nameData, err := readAligned4(sr, n.NameSize)
			if err != nil {
				return 0, fmt.Errorf("read note name: %w", err)
			}
			name = strings.Trim(string(nameData), "\x00")
		}
		if n.DescSize > 0 {
			if name == "Linux" && n.DescSize == 4 && n.Type == 0 {
				desc, err := readAligned4(sr, n.DescSize)
				if err != nil {
					return 0, fmt.Errorf("read note desc: %w", err)
				}
				return hdr.ByteOrder.Uint32(desc), nil
			}
			full := int64((n.DescSize + 3) &^ 3)
			_, err := sr.Seek(full, io.SeekCurrent)
			if err != nil {
				return 0, fmt.Errorf("seek past note desc: %w", err)
			}
		}
	}
	return 0, fmt.Errorf("linux version note not found")
}

func readAligned4(r io.Reader, sz int32) ([]byte, error) {
	full := (sz + 3) &^ 3
	data := make([]byte, full)
	_, err := io.ReadFull(r, data)
	if err != nil {
		return nil, err
	}
	return data[:sz], nil
}
