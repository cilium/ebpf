package ebpf

import (
	"bufio"
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
}

func newMapInfoFromFd(fd *internal.FD) (*MapInfo, error) {
	info, err := bpfGetMapInfoByFD(fd)
	if errors.Is(err, syscall.EINVAL) {
		return newMapInfoFromProc(fd)
	}
	if err != nil {
		return nil, err
	}

	return &MapInfo{
		MapType(info.map_type),
		info.key_size,
		info.value_size,
		info.max_entries,
		info.map_flags,
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
}

func newProgramInfoFromFd(fd *internal.FD) (*ProgramInfo, error) {
	info, err := bpfGetProgInfoByFD(fd)
	if errors.Is(err, syscall.EINVAL) {
		return newProgramInfoFromProc(fd)
	}
	if err != nil {
		return nil, err
	}

	return &ProgramInfo{
		ProgramType(info.prog_type),
	}, nil
}

func newProgramInfoFromProc(fd *internal.FD) (*ProgramInfo, error) {
	var info ProgramInfo

	err := scanFdInfo(fd, map[string]interface{}{
		"prog_type": &info.Type,
	})
	if errors.Is(err, errMissingFields) {
		return nil, &internal.UnsupportedFeatureError{
			Name:           "reading program info from /proc/self/fdinfo",
			MinimumVersion: internal.Version{4, 10, 0},
		}
	}
	if err != nil {
		return nil, err
	}

	return &info, nil
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
