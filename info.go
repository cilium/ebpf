package ebpf

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/internal"
)

// MapInfo describes a map.
//
// The pointer fields are not supported across all kernels, and may be nil.
type MapInfo struct {
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	// Name as supplied by user space at load time.
	Name *string
}

func newMapInfoFromFd(fd *internal.FD) (*MapInfo, error) {
	info, err := bpfGetMapInfoByFD(fd)
	if errors.Is(err, syscall.EINVAL) {
		return newMapInfoFromProc(fd)
	}
	if err != nil {
		return nil, err
	}

	// name is available from 4.15. Unfortunately we can't discern between
	// an unnamed map and a kernel that doesn't support names.
	name := strPtr(internal.CString(info.name[:]))

	return &MapInfo{
		MapType(info.map_type),
		info.key_size,
		info.value_size,
		info.max_entries,
		info.map_flags,
		name,
	}, nil
}

func newMapInfoFromProc(fd *internal.FD) (*MapInfo, error) {
	var mi MapInfo
	err := scanFdInfo(fd, map[string]interface{}{
		"map_type":    &mi.Type,
		"key_size":    &mi.KeySize,
		"value_size":  &mi.ValueSize,
		"max_entries": &mi.MaxEntries,
		"map_flags":   &mi.Flags,
	})
	if err != nil {
		return nil, err
	}
	return &mi, nil
}

// ProgramInfo describes a program.
//
// The pointer fields are not supported across all kernels, and may be nil.
type ProgramInfo struct {
	Type ProgramType
	// Truncated hash of the BPF bytecode.
	Tag *string
	// Name as supplied by user space at load time.
	Name *string
}

func newProgramInfoFromFd(fd *internal.FD) (*ProgramInfo, error) {
	info, err := bpfGetProgInfoByFD(fd)
	if errors.Is(err, syscall.EINVAL) {
		return newProgramInfoFromProc(fd)
	}
	if err != nil {
		return nil, err
	}

	// tag is available if the kernel supports BPF_PROG_GET_INFO_BY_FD.
	tag := strPtr(hex.EncodeToString(info.tag[:]))

	// name is available from 4.15. To distinguish an unnamed program from
	// a kernel that doesn't support names we can check whether load_time is
	// present, since that also appeared in the same kernel version.
	var name *string
	if info.load_time > 0 {
		name = strPtr(internal.CString(info.name[:]))
	}

	return &ProgramInfo{
		ProgramType(info.prog_type),
		tag,
		name,
	}, nil
}

func newProgramInfoFromProc(fd *internal.FD) (*ProgramInfo, error) {
	var (
		tag string
		abi = ProgramInfo{Tag: &tag}
	)
	err := scanFdInfo(fd, map[string]interface{}{
		"prog_type": &abi.Type,
		"prog_tag":  &tag,
	})
	if errors.Is(err, errMissingFields) {
		return nil, &internal.UnsupportedFeatureError{
			Name:           "reading ABI from /proc/self/fdinfo",
			MinimumVersion: internal.Version{4, 10, 0},
		}
	}
	if err != nil {
		return nil, err
	}

	return &abi, nil
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
		return fmt.Errorf("%s: %w", fh.Name(), err)
	}
	return nil
}

var errMissingFields = errors.New("missing fields")

func scanFdInfoReader(r io.Reader, fields map[string]interface{}) error {
	var (
		scanner = bufio.NewScanner(r)
		scanned int
	)

	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSuffix(parts[0], ":")
		field, ok := fields[string(name)]
		if !ok {
			continue
		}

		if n, err := fmt.Sscanln(parts[1], field); err != nil || n != 1 {
			return fmt.Errorf("can't parse field %s: %v", name, err)
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

func strPtr(str string) *string {
	return &str
}
