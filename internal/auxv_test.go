package internal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

type auxvFileReader struct {
	file            *os.File
	order           binary.ByteOrder
	uintptrIs32bits bool
}

func (r *auxvFileReader) Close() error {
	return r.file.Close()
}

type auxvPair32 struct {
	Tag, Value uint32
}

type auxvPair64 struct {
	Tag, Value uint64
}

func (r *auxvFileReader) ReadAuxvPair() (tag, value uint64, _ error) {
	if r.uintptrIs32bits {
		var aux auxvPair32
		if err := binary.Read(r.file, r.order, &aux); err != nil {
			return 0, 0, fmt.Errorf("reading auxv entry: %w", err)
		}
		return uint64(aux.Tag), uint64(aux.Value), nil
	}

	var aux auxvPair64
	if err := binary.Read(r.file, r.order, &aux); err != nil {
		return 0, 0, fmt.Errorf("reading auxv entry: %w", err)
	}
	return aux.Tag, aux.Value, nil
}

func newAuxFileReader(path string, order binary.ByteOrder, uintptrIs32bits bool) (auxvPairReader, error) {
	// Read data from the auxiliary vector, which is normally passed directly
	// to the process. Go does not expose that data before go 1.21, so we must read it from procfs.
	// https://man7.org/linux/man-pages/man3/getauxval.3.html
	av, err := os.Open(path)
	if errors.Is(err, unix.EACCES) {
		return nil, fmt.Errorf("opening auxv: %w (process may not be dumpable due to file capabilities)", err)
	}
	if err != nil {
		return nil, fmt.Errorf("opening auxv: %w", err)
	}

	return &auxvFileReader{
		file:            av,
		order:           order,
		uintptrIs32bits: uintptrIs32bits,
	}, nil
}

func newDefaultAuxvFileReader() (auxvPairReader, error) {
	const uintptrIs32bits = unsafe.Sizeof((uintptr)(0)) == 4
	return newAuxFileReader("/proc/self/auxv", NativeEndian, uintptrIs32bits)
}

func TestAuxvBothSourcesEqual(t *testing.T) {
	runtimeBased, err := newAuxvRuntimeReader()
	if err != nil {
		t.Fatal(err)
	}
	fileBased, err := newDefaultAuxvFileReader()
	if err != nil {
		t.Fatal(err)
	}

	for {
		runtimeTag, runtimeValue, err := runtimeBased.ReadAuxvPair()
		if err != nil {
			t.Fatal(err)
		}

		fileTag, fileValue, err := fileBased.ReadAuxvPair()
		if err != nil {
			t.Fatal(err)
		}

		if runtimeTag != fileTag {
			t.Errorf("mismatching tags: runtime=%v, file=%v", runtimeTag, fileTag)
		}

		if runtimeValue != fileValue {
			t.Errorf("mismatching values: runtime=%v, file=%v", runtimeValue, fileValue)
		}

		if runtimeTag == _AT_NULL {
			break
		}
	}
}
