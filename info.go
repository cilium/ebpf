package ebpf

import (
	"bufio"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/btf"

	"github.com/juju/fslock"
)

var defaultMapInfoPersistentFile = filepath.Join(os.TempDir(), "cilium-maps-info-v0.1")

var _mapInfoPersistent *mapInfoPersistent

func init() {
	if err := haveFdInfoMaps(); err != nil && errors.Is(err, ErrNotSupported) {
		mip, err := newMapInfoPersistent()
		if err == nil {
			_mapInfoPersistent = mip
		}
	}
}

type mapInfoPersistent struct {
	lockFile string
	infoPath map[string]MapInfo
	lock     *fslock.Lock
}

func newMapInfoPersistent(lockFile ...string) (mip *mapInfoPersistent, err error) {
	lock := defaultMapInfoPersistentFile
	if len(lockFile) > 0 {
		lock = lockFile[0]
	}
	mip = &mapInfoPersistent{
		lockFile: lock,
		infoPath: make(map[string]MapInfo),
		lock:     fslock.New(lock),
	}
	err = mip.lock.Lock()
	if err != nil {
		return nil, err
	}
	defer func() { _ = mip.lock.Unlock() }()
	if err = mip.loadMapsInfo(); err != nil {
		return nil, err
	}
	return mip, nil
}

func (mip *mapInfoPersistent) loadMapsInfo() error {
	f, err := os.Open(mip.lockFile)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() == 0 {
		return nil
	}

	d := gob.NewDecoder(f)
	err = d.Decode(&mip.infoPath)
	if err != nil {
		return fmt.Errorf("failed gob decode '%s': %w", mip.lockFile, err)
	}
	return nil
}

func (mip *mapInfoPersistent) saveMapsInfo() error {
	f, err := os.OpenFile(mip.lockFile, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	e := gob.NewEncoder(f)
	err = e.Encode(mip.infoPath)
	if err != nil {
		return fmt.Errorf("failed gob encode '%s': %w", mip.lockFile, err)
	}
	return nil
}

func (mip *mapInfoPersistent) Info(filename string) (mi *MapInfo, err error) {
	err = mip.lock.Lock()
	if err != nil {
		return nil, err
	}
	defer func() { _ = mip.lock.Unlock() }()

	if err = mip.loadMapsInfo(); err != nil {
		return nil, err
	}

	info, found := mip.infoPath[filename]
	if !found {
		return nil, fmt.Errorf("filename '%s': %w", filename, os.ErrNotExist)
	}
	return &info, nil
}

func (mip *mapInfoPersistent) Pin(m *Map, oldFilename string, filename string) error {
	err := mip.lock.Lock()
	if err != nil {
		return err
	}
	defer func() { _ = mip.lock.Unlock() }()

	if oldFilename != "" {
		delete(mip.infoPath, oldFilename)
	}
	return mip.save(m, filename)
}

func (mip *mapInfoPersistent) Unpin(filename string) error {
	err := mip.lock.Lock()
	if err != nil {
		return err
	}
	defer func() { _ = mip.lock.Unlock() }()
	delete(mip.infoPath, filename)
	return mip.saveMapsInfo()
}

func (mip *mapInfoPersistent) save(m *Map, filename string) error {
	info := MapInfo{
		Name:       m.name,
		Type:       m.typ,
		KeySize:    m.keySize,
		ValueSize:  m.valueSize,
		MaxEntries: m.maxEntries,
		Flags:      m.flags,
	}
	mip.infoPath[filename] = info

	return mip.saveMapsInfo()
}

var haveFdInfoMaps = internal.FeatureTest("proc/pid/fdinfo maps", "4.9?", func() error {
	// This checks we can scan /proc/pid/fdinfo, which appeared in 4.9?.
	m, err := internal.BPFMapCreate(&internal.BPFMapCreateAttr{
		MapType:    uint32(Array),
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	var mi MapInfo
	err = scanFdInfo(m, map[string]interface{}{
		"map_type":    &mi.Type,
		"key_size":    &mi.KeySize,
		"value_size":  &mi.ValueSize,
		"max_entries": &mi.MaxEntries,
		"map_flags":   &mi.Flags,
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	_ = m.Close()
	return nil
})

// MapInfo describes a map.
type MapInfo struct {
	Type       MapType
	id         MapID
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	// Name as supplied by user space at load time.
	Name string
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
		MapID(info.id),
		info.key_size,
		info.value_size,
		info.max_entries,
		info.map_flags,
		// name is available from 4.15.
		internal.CString(info.name[:]),
	}, nil
}

func newMapInfoFromProc(fd *internal.FD) (*MapInfo, error) {
	if err := haveFdInfoMaps(); err != nil {
		return nil, err
	}

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

// ID returns the map ID.
//
// Available from 4.13.
//
// The bool return value indicates whether this optional field is available.
func (mi *MapInfo) ID() (MapID, bool) {
	return mi.id, mi.id > 0
}

// programStats holds statistics of a program.
type programStats struct {
	// Total accumulated runtime of the program ins ns.
	runtime time.Duration
	// Total number of times the program was called.
	runCount uint64
}

// ProgramInfo describes a program.
type ProgramInfo struct {
	Type ProgramType
	id   ProgramID
	// Truncated hash of the BPF bytecode.
	Tag string
	// Name as supplied by user space at load time.
	Name string
	// BTF for the program.
	btf btf.ID
	// IDS map ids related to program.
	ids []MapID

	stats *programStats
}

func newProgramInfoFromFd(fd *internal.FD) (*ProgramInfo, error) {
	info, err := bpfGetProgInfoByFD(fd, nil)
	if errors.Is(err, syscall.EINVAL) {
		return newProgramInfoFromProc(fd)
	}
	if err != nil {
		return nil, err
	}

	var mapIDs []MapID
	if info.nr_map_ids > 0 {
		mapIDs = make([]MapID, info.nr_map_ids)
		info, err = bpfGetProgInfoByFD(fd, mapIDs)
		if err != nil {
			return nil, err
		}
	}

	return &ProgramInfo{
		Type: ProgramType(info.prog_type),
		id:   ProgramID(info.id),
		// tag is available if the kernel supports BPF_PROG_GET_INFO_BY_FD.
		Tag: hex.EncodeToString(info.tag[:]),
		// name is available from 4.15.
		Name: internal.CString(info.name[:]),
		btf:  btf.ID(info.btf_id),
		ids:  mapIDs,
		stats: &programStats{
			runtime:  time.Duration(info.run_time_ns),
			runCount: info.run_cnt,
		},
	}, nil
}

func newProgramInfoFromProc(fd *internal.FD) (*ProgramInfo, error) {
	var info ProgramInfo
	err := scanFdInfo(fd, map[string]interface{}{
		"prog_type": &info.Type,
		"prog_tag":  &info.Tag,
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

// ID returns the program ID.
//
// Available from 4.13.
//
// The bool return value indicates whether this optional field is available.
func (pi *ProgramInfo) ID() (ProgramID, bool) {
	return pi.id, pi.id > 0
}

// BTFID returns the BTF ID associated with the program.
//
// Available from 5.0.
//
// The bool return value indicates whether this optional field is available and
// populated. (The field may be available but not populated if the kernel
// supports the field but the program was loaded without BTF information.)
func (pi *ProgramInfo) BTFID() (btf.ID, bool) {
	return pi.btf, pi.btf > 0
}

// RunCount returns the total number of times the program was called.
//
// Can return 0 if the collection of statistics is not enabled. See EnableStats().
// The bool return value indicates whether this optional field is available.
func (pi *ProgramInfo) RunCount() (uint64, bool) {
	if pi.stats != nil {
		return pi.stats.runCount, true
	}
	return 0, false
}

// Runtime returns the total accumulated runtime of the program.
//
// Can return 0 if the collection of statistics is not enabled. See EnableStats().
// The bool return value indicates whether this optional field is available.
func (pi *ProgramInfo) Runtime() (time.Duration, bool) {
	if pi.stats != nil {
		return pi.stats.runtime, true
	}
	return time.Duration(0), false
}

// MapIDs returns the maps related to the program.
//
// The bool return value indicates whether this optional field is available.
func (pi *ProgramInfo) MapIDs() ([]MapID, bool) {
	return pi.ids, pi.ids != nil
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

// EnableStats starts the measuring of the runtime
// and run counts of eBPF programs.
//
// Collecting statistics can have an impact on the performance.
//
// Requires at least 5.8.
func EnableStats(which uint32) (io.Closer, error) {
	attr := internal.BPFEnableStatsAttr{
		StatsType: which,
	}

	fd, err := internal.BPFEnableStats(&attr)
	if err != nil {
		return nil, err
	}
	return fd, nil
}
