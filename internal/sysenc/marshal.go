package sysenc

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf/internal"
)

var bytesBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Marshal turns data into a byte slice using the system's native endianness.
//
// Returns an error if the data can't be turned into a byte slice according to
// the behaviour of [binary.Write].
func Marshal(data any, size int) (Buffer, error) {
	if data == nil {
		return Buffer{}, errors.New("can't marshal a nil value")
	}

	layout := dataLayout{1, size, size}

	var buf []byte
	var err error
	switch value := data.(type) {
	case encoding.BinaryMarshaler: // TODO: Should we support this here?
		buf, err = value.MarshalBinary()
	case string:
		// Replace with unsafe.Slice(unsafe.StringData()) once we target go 1.20.
		buf = []byte(value)
	case []byte:
		buf = value
	case int16:
		buf = internal.NativeEndian.AppendUint16(make([]byte, 0, 2), uint16(value))
	case uint16:
		buf = internal.NativeEndian.AppendUint16(make([]byte, 0, 2), value)
	case int32:
		buf = internal.NativeEndian.AppendUint32(make([]byte, 0, 4), uint32(value))
	case uint32:
		buf = internal.NativeEndian.AppendUint32(make([]byte, 0, 4), value)
	case int64:
		buf = internal.NativeEndian.AppendUint64(make([]byte, 0, 8), uint64(value))
	case uint64:
		buf = internal.NativeEndian.AppendUint64(make([]byte, 0, 8), value)
	default:
		if buf := unsafeBackingMemory(data, layout); buf != nil {
			return newBuffer(buf, layout), nil
		}

		wr := bytesBufferPool.Get().(*bytes.Buffer)
		defer bytesBufferPool.Put(wr)

		// Reinitialize the Buffer with a new backing slice since it is returned to
		// the caller by wr.Bytes() below. Pooling is faster despite calling
		// NewBuffer. The pooled alloc is still reused, it only needs to be zeroed.
		*wr = *bytes.NewBuffer(make([]byte, 0, size))

		err = binary.Write(wr, internal.NativeEndian, value)
		buf = wr.Bytes()
	}
	if err != nil {
		return Buffer{}, err
	}

	if len(buf) != size {
		return Buffer{}, fmt.Errorf("%T doesn't marshal to %d bytes", data, size)
	}

	return newBuffer(buf, layout), nil
}

var bytesReaderPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Reader)
	},
}

func Unmarshal(data interface{}, buf []byte) error {
	switch value := data.(type) {
	case encoding.BinaryUnmarshaler:
		return value.UnmarshalBinary(buf)

	case *string:
		*value = string(buf)
		return nil

	default:
		if dataBuf := unsafeBackingMemory(data, dataLayout{1, len(buf), len(buf)}); dataBuf != nil {
			copy(dataBuf, buf)
			return nil
		}

		rd := bytesReaderPool.Get().(*bytes.Reader)
		defer bytesReaderPool.Put(rd)

		rd.Reset(buf)

		return binary.Read(rd, internal.NativeEndian, value)
	}
}

// unsafeBackingMemory returns the backing memory of data if it matches the
// given layout.
//
// Returns nil if the layout is not compatible.
func unsafeBackingMemory(data any, layout dataLayout) []byte {
	if data == nil || !layout.valid() {
		return nil
	}

	if kind := reflect.TypeOf(data).Kind(); kind != reflect.Pointer && kind != reflect.Slice {
		// Prevent Value.UnsafePointer from panicking.
		return nil
	}

	haveLayout := layoutOf(data)
	if layout.count == 1 {
		// Allow arrays and slices if they have the correct size.
		haveLayout.normalise()
	}
	if layout.size == layout.stride {
		// Skip trailing padding if the target doesn't have any padding either.
		// This enables *struct{ uint32; uint16 } to use the zero copy mechanism.
		haveLayout.truncate()
	}
	if layout != haveLayout {
		return nil
	}

	return unsafe.Slice((*byte)(reflect.ValueOf(data).UnsafePointer()), layout.length())
}
