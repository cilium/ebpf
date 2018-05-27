package ebpf

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"unsafe"

	"github.com/pkg/errors"
)

var nativeEndian binary.ByteOrder

func init() {
	if isBigEndian() {
		nativeEndian = binary.BigEndian
	} else {
		nativeEndian = binary.LittleEndian
	}
}

func isBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}

// Marshaler allows controlling the binary representation used for getting
// and setting keys on a map.
type Marshaler interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func marshalBytes(data interface{}, length int) (buf []byte, err error) {
	switch value := data.(type) {
	case encoding.BinaryMarshaler:
		buf, err = value.MarshalBinary()
	case string:
		buf = []byte(value)
	case []byte:
		buf = value
	default:
		var wr bytes.Buffer
		err = binary.Write(&wr, nativeEndian, value)
		err = errors.Wrapf(err, "encoding %T", value)
		buf = wr.Bytes()
	}
	if err != nil {
		return nil, err
	}

	if len(buf) != length {
		return nil, errors.Errorf("%T must marshal to %d bytes", data, length)
	}
	return buf, nil
}

func unmarshalBytes(data interface{}, buf []byte) error {
	switch value := data.(type) {
	case encoding.BinaryUnmarshaler:
		return value.UnmarshalBinary(buf)
	case *string:
		*value = string(buf)
		return nil
	case *[]byte:
		*value = buf
		return nil
	case string:
		return errors.New("require pointer to string")
	case []byte:
		return errors.New("require pointer to []byte")
	default:
		rd := bytes.NewReader(buf)
		err := binary.Read(rd, nativeEndian, value)
		return errors.Wrapf(err, "decoding %T", value)
	}
}
