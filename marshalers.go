package ebpf

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"reflect"
	"sync"
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

// marshalPerCPUValue encodes a slice containing one value per
// possible CPU into a buffer of bytes.
//
// Values are initialized to zero if the slice has less elements than CPUs.
//
// slice must have a type like []elementType
func marshalPerCPUValue(slice interface{}, elemLength int) ([]byte, error) {
	sliceType := reflect.TypeOf(slice)
	if sliceType.Kind() != reflect.Slice {
		return nil, errors.New("per-CPU value requires slice")
	}

	possibleCPUs, err := possibleCPUs()
	if err != nil {
		return nil, err
	}

	sliceValue := reflect.ValueOf(slice)
	sliceLen := sliceValue.Len()
	if sliceLen > possibleCPUs {
		return nil, errors.Errorf("per-CPU value exceeds number of CPUs")
	}

	alignedElemLength := align(elemLength, 8)
	buf := make([]byte, alignedElemLength*possibleCPUs)

	for i := 0; i < sliceLen; i++ {
		elem := sliceValue.Index(i).Interface()
		elemBytes, err := marshalBytes(elem, elemLength)
		if err != nil {
			return nil, err
		}

		offset := i * alignedElemLength
		copy(buf[offset:offset+elemLength], elemBytes)
	}

	return buf, nil
}

// unmarshalPerCPUValue decodes a buffer into a slice containing one value per
// possible CPU.
//
// valueOut must have a type like *[]elementType
func unmarshalPerCPUValue(slicePtr interface{}, elemLength int, buf []byte) error {
	slicePtrType := reflect.TypeOf(slicePtr)
	if slicePtrType.Kind() != reflect.Ptr || slicePtrType.Elem().Kind() != reflect.Slice {
		return errors.Errorf("per-cpu value requires pointer to slice")
	}

	possibleCPUs, err := possibleCPUs()
	if err != nil {
		return err
	}

	sliceType := slicePtrType.Elem()
	slice := reflect.MakeSlice(sliceType, possibleCPUs, possibleCPUs)

	sliceElemType := sliceType.Elem()
	sliceElemIsPointer := sliceElemType.Kind() == reflect.Ptr
	if sliceElemIsPointer {
		sliceElemType = sliceElemType.Elem()
	}

	step := len(buf) / possibleCPUs
	if step < elemLength {
		return errors.Errorf("per-cpu element length is larger than available data")
	}
	for i := 0; i < possibleCPUs; i++ {
		var elem interface{}
		if sliceElemIsPointer {
			newElem := reflect.New(sliceElemType)
			slice.Index(i).Set(newElem)
			elem = newElem.Interface()
		} else {
			elem = slice.Index(i).Addr().Interface()
		}

		// Make a copy, since unmarshal can hold on to itemBytes
		elemBytes := make([]byte, elemLength)
		copy(elemBytes, buf[:elemLength])

		err := unmarshalBytes(elem, elemBytes)
		if err != nil {
			return errors.Wrapf(err, "cpu %d", i)
		}

		buf = buf[step:]
	}

	reflect.ValueOf(slicePtr).Elem().Set(slice)
	return nil
}

var sysCPU struct {
	once sync.Once
	err  error
	num  int
}

// possibleCPUs returns the max number of CPUs a system may possibly have
// Logical CPU numbers must be of the form 0-n
func possibleCPUs() (int, error) {
	sysCPU.once.Do(func() {
		sysCPU.num, sysCPU.err = parseCPUs("/sys/devices/system/cpu/possible")
	})

	return sysCPU.num, sysCPU.err
}

var onlineCPU struct {
	once sync.Once
	err  error
	num  int
}

// onlineCPUs returns the number of currently online CPUs
// Logical CPU numbers must be of the form 0-n
func onlineCPUs() (int, error) {
	onlineCPU.once.Do(func() {
		onlineCPU.num, onlineCPU.err = parseCPUs("/sys/devices/system/cpu/online")
	})

	return onlineCPU.num, onlineCPU.err
}

// parseCPUs parses the number of cpus from sysfs,
// in the format of "/sys/devices/system/cpu/{possible,online,..}.
// Logical CPU numbers must be of the form 0-n
func parseCPUs(path string) (int, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, errors.Wrapf(err, "reading %s", path)
	}

	var cpus int
	_, err = fmt.Fscanf(bytes.NewReader(buf), "0-%d\n", &cpus)
	if err != nil {
		return 0, errors.Wrapf(err, "%s has unknown format", path)
	}

	// cpus is 0 indexed
	return cpus + 1, nil
}

func align(n, alignment int) int {
	return (int(n) + alignment - 1) / alignment * alignment
}
