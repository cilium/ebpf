package sys

import (
	"errors"
	"math"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/internal/errno"
	"github.com/cilium/ebpf/internal/testutils/testmain"

	"github.com/go-quicktest/qt"
)

func TestMap(t *testing.T) {
	fd, err := MapCreate(&MapCreateAttr{
		MapType:    BPF_MAP_TYPE_HASH,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(func() {
		qt.Assert(t, qt.IsNil(fd.Close()))
	})

	nextIdAttr := &MapGetNextIdAttr{Id: 0}
	qt.Assert(t, qt.IsNil(MapGetNextId(nextIdAttr)))
	qt.Check(t, qt.Not(qt.Equals(nextIdAttr.NextId, 0)))

	key := NewPointer(unsafe.Pointer(new(uint32)))
	value := []byte{10, 20, 30, 40}

	qt.Assert(t, qt.IsNil(MapUpdateElem(&MapUpdateElemAttr{
		MapFd: fd.Uint(),
		Key:   key,
		Value: NewSlicePointer(value),
	})))

	out := make([]byte, len(value))
	qt.Assert(t, qt.IsNil(MapLookupElem(&MapLookupElemAttr{
		MapFd: fd.Uint(),
		Key:   key,
		Value: NewSlicePointer(out),
	})))
	qt.Assert(t, qt.DeepEquals(out, value))

	qt.Assert(t, qt.IsNil(MapDeleteElem(&MapDeleteElemAttr{
		MapFd: fd.Uint(),
		Key:   key,
	})))

	qt.Assert(t, qt.IsNotNil(MapLookupElem(&MapLookupElemAttr{
		MapFd: fd.Uint(),
		Key:   key,
		Value: NewSlicePointer(out),
	})))
}

func TestBPFAllocations(t *testing.T) {
	n := testing.AllocsPerRun(10, func() {
		var attr struct {
			Foo uint64
		}

		BPF(math.MaxUint32, unsafe.Pointer(&attr), 0)
	})
	qt.Assert(t, qt.Equals(n, 0))
}

func TestObjName(t *testing.T) {
	name := NewObjName("more_than_16_characters_long")
	if name[len(name)-1] != 0 {
		t.Error("NewBPFObjName doesn't null terminate")
	}
	if len(name) != BPF_OBJ_NAME_LEN {
		t.Errorf("Name is %d instead of %d bytes long", len(name), BPF_OBJ_NAME_LEN)
	}
}

func TestSyscallError(t *testing.T) {
	err := errors.New("foo")
	foo := Error(err, errno.EINVAL)

	if !errors.Is(foo, errno.EINVAL) {
		t.Error("SyscallError is not the wrapped errno")
	}

	if !errors.Is(foo, err) {
		t.Error("SyscallError is not the wrapped error")
	}

	if errors.Is(errno.EINVAL, foo) {
		t.Error("Errno is the SyscallError")
	}

	if errors.Is(err, foo) {
		t.Error("Error is the SyscallError")
	}
}

func TestMain(m *testing.M) {
	testmain.Run(m)
}
