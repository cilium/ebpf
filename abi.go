package ebpf

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/cilium/ebpf/internal"

	"golang.org/x/xerrors"
)

// MapABI are the attributes of a Map which are available across all supported kernels.
type MapABI struct {
	Type          MapType
	ID            MapID
	KeySize       uint32
	ValueSize     uint32
	MaxEntries    uint32
	Flags         uint32
	Name          string
	OwnerProgType ProgramType
}

func newMapABIFromSpec(spec *MapSpec) *MapABI {
	return &MapABI{
		spec.Type,
		0,
		spec.KeySize,
		spec.ValueSize,
		spec.MaxEntries,
		spec.Flags,
		spec.Name,
		UnspecifiedProgram,
	}
}

func newMapABIFromFd(fd *internal.FD) (string, *MapABI, error) {
	info, err := bpfGetMapInfoByFD(fd)
	if err != nil {
		if xerrors.Is(err, syscall.EINVAL) {
			abi, err := newMapABIFromProc(fd)
			return "", abi, err
		}
		return "", nil, err
	}

	return "", &MapABI{
		MapType(info.mapType),
		MapID(info.id),
		info.keySize,
		info.valueSize,
		info.maxEntries,
		info.flags,
		internal.CString(info.mapName[:]),
		UnspecifiedProgram,
	}, nil
}

func newMapABIFromProc(fd *internal.FD) (*MapABI, error) {
	var abi MapABI
	fields := map[string]interface{}{
		"map_type":    &abi.Type,
		"key_size":    &abi.KeySize,
		"value_size":  &abi.ValueSize,
		"max_entries": &abi.MaxEntries,
		"map_flags":   &abi.Flags,
		"map_id":      &abi.ID,
	}
	if abi.Type == ProgramArray {
		fields["owner_prog_type"] = &abi.OwnerProgType
	}

	err := scanFdInfo(fd, fields)
	if xerrors.Is(err, errMissingFields) {
		return nil, &internal.UnsupportedFeatureError{
			Name:           "reading map ABI from /proc/self/fdinfo",
			MinimumVersion: internal.Version{4, 5, 0},
		}
	}

	if err != nil {
		return nil, err
	}

	return &abi, nil
}

// Equal returns true if two ABIs have the same values.
func (abi *MapABI) Equal(other *MapABI) bool {
	switch {
	case abi.Type != other.Type:
		return false
	case abi.ID != other.ID:
		return false
	case abi.KeySize != other.KeySize:
		return false
	case abi.ValueSize != other.ValueSize:
		return false
	case abi.MaxEntries != other.MaxEntries:
		return false
	case abi.Flags != other.Flags:
		return false
	case abi.Name != other.Name:
		return false
	case abi.OwnerProgType != other.OwnerProgType:
		return false
	default:
		return true
	}
}

// ProgramABI are the attributes of a Program which are available across all supported kernels.
type ProgramABI struct {
	Type ProgramType
}

func newProgramABIFromSpec(spec *ProgramSpec) *ProgramABI {
	return &ProgramABI{
		spec.Type,
	}
}

func newProgramABIFromFd(fd *internal.FD) (string, *ProgramABI, error) {
	info, err := bpfGetProgInfoByFD(fd)
	if err != nil {
		if xerrors.Is(err, syscall.EINVAL) {
			return newProgramABIFromProc(fd)
		}

		return "", nil, err
	}

	var name string
	if bpfName := internal.CString(info.name[:]); bpfName != "" {
		name = bpfName
	} else {
		name = internal.CString(info.tag[:])
	}

	return name, &ProgramABI{
		Type: ProgramType(info.progType),
	}, nil
}

func newProgramABIFromProc(fd *internal.FD) (string, *ProgramABI, error) {
	var (
		abi  ProgramABI
		name string
	)

	err := scanFdInfo(fd, map[string]interface{}{
		"prog_type": &abi.Type,
		"prog_tag":  &name,
	})
	if xerrors.Is(err, errMissingFields) {
		return "", nil, &internal.UnsupportedFeatureError{
			Name:           "reading program ABI from /proc/self/fdinfo",
			MinimumVersion: internal.Version{4, 11, 0},
		}
	}
	if err != nil {
		return "", nil, err
	}

	return name, &abi, nil
}

func scanFdInfo(fd *internal.FD, fields map[string]interface{}) error {
	raw, err := fd.Value()
	if err != nil {
		return err
	}

	fh, err := os.Open(fmt.Sprintf("/proc/self/fdinfo/%d", raw))
	if err != nil {
		return err
	}
	defer fh.Close()

	if err := scanFdInfoReader(fh, fields); err != nil {
		return xerrors.Errorf("%s: %w", fh.Name(), err)
	}
	return nil
}

var errMissingFields = xerrors.New("missing fields")

func scanFdInfoReader(r io.Reader, fields map[string]interface{}) error {
	var (
		scanner = bufio.NewScanner(r)
		scanned int
	)

	for scanner.Scan() {
		parts := bytes.SplitN(scanner.Bytes(), []byte("\t"), 2)
		if len(parts) != 2 {
			continue
		}

		name := bytes.TrimSuffix(parts[0], []byte(":"))
		field, ok := fields[string(name)]
		if !ok {
			continue
		}

		if n, err := fmt.Fscanln(bytes.NewReader(parts[1]), field); err != nil || n != 1 {
			return xerrors.Errorf("can't parse field %s: %v", name, err)
		}

		scanned++
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if scanned != len(fields) {
		return errMissingFields
	}

	return nil
}

// Equal returns true if two ABIs have the same values.
func (abi *ProgramABI) Equal(other *ProgramABI) bool {
	switch {
	case abi.Type != other.Type:
		return false
	default:
		return true
	}
}
