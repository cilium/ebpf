package manager

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/gopsutil/process"
	"github.com/florianl/go-tc"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/DataDog/ebpf"
)

// ConstantEditor - A constant editor tries to rewrite the value of a constant in a compiled eBPF program.
//
// Constant edition only works before the eBPF programs are loaded in the kernel, and therefore before the
// Manager is started. If no program sections are provided, the manager will try to edit the constant in all eBPF programs.
type ConstantEditor struct {
	// Name - Name of the constant to rewrite
	Name string

	// Value - Value to write in the eBPF bytecode. When using the asm load method, the Value has to be a uint64.
	Value interface{}

	// FailOnMissing - If FailOMissing is set to true, the constant edition process will return an error if the constant
	// was missing in at least one program
	FailOnMissing bool

	// ProbeIdentificationPairs - Identifies the list of programs to edit. If empty, it will apply to all the programs
	// of the manager. Will return an error if at least one edition failed.
	ProbeIdentificationPairs []ProbeIdentificationPair
}

// TailCallRoute - A tail call route defines how tail calls should be routed between eBPF programs.
//
// The provided eBPF program will be inserted in the provided eBPF program array, at the provided key. The eBPF program
// can be provided by its section or by its *ebpf.Program representation.
type TailCallRoute struct {
	// ProgArrayName - Name of the BPF_MAP_TYPE_PROG_ARRAY map as defined in its section SEC("maps/[ProgArray]")
	ProgArrayName string

	// Key - Key at which the program will be inserted in the ProgArray map
	Key uint32

	// ProbeIdentificationPair - Selector of the program to insert in the ProgArray map
	ProbeIdentificationPair ProbeIdentificationPair

	// Program - Program to insert in the ProgArray map
	Program *ebpf.Program
}

// MapRoute - A map route defines how multiple maps should be routed between eBPF programs.
//
// The provided eBPF map will be inserted in the provided eBPF array of maps (or hash of maps), at the provided key. The
// inserted eBPF map can be provided by its section or by its *ebpf.Map representation.
type MapRoute struct {
	// RoutingMapName - Name of the BPF_MAP_TYPE_ARRAY_OF_MAPS or BPF_MAP_TYPE_HASH_OF_MAPS map, as defined in its
	// section SEC("maps/[RoutingMapName]")
	RoutingMapName string

	// Key - Key at which the program will be inserted in the routing map
	Key interface{}

	// RoutedName - Section of the map that will be inserted
	RoutedName string

	// Map - Map to insert in the routing map
	Map *ebpf.Map
}

// MapSpecEditorFlag - Flag used to specify what a MapSpecEditor should edit.
type MapSpecEditorFlag uint

const (
	EditType       MapSpecEditorFlag = 1 << 1
	EditMaxEntries MapSpecEditorFlag = 1 << 2
	EditFlags      MapSpecEditorFlag = 1 << 3
)

// MapSpecEditor - A MapSpec editor defines how specific parameters of specific maps should be updated at runtime
//
// For example, this can be used if you need to change the max_entries of a map before it is loaded in the kernel, but
// you don't know what this value should be initially.
type MapSpecEditor struct {
	// Type - Type of the map.
	Type ebpf.MapType
	// MaxEntries - Max Entries of the map.
	MaxEntries uint32
	// Flags - Flags provided to the kernel during the loading process.
	Flags uint32
	// EditorFlag - Use this flag to specify what fields should be updated. See MapSpecEditorFlag.
	EditorFlag MapSpecEditorFlag
}

// ProbesSelector - A probe selector defines how a probe (or a group of probes) should be activated.
//
// For example, this can be used to specify that out of a group of optional probes, at least one should be activated.
type ProbesSelector interface {
	// GetProbesIdentificationPairList - Returns the list of probes that this selector activates
	GetProbesIdentificationPairList() []ProbeIdentificationPair
	// RunValidator - Ensures that the probes that were successfully activated follow the selector goal.
	// For example, see OneOf.
	RunValidator(manager *Manager) error
	// EditProbeIdentificationPair - Changes all the selectors looking for the old ProbeIdentificationPair so that they
	// mow select the new one
	EditProbeIdentificationPair(old ProbeIdentificationPair, new ProbeIdentificationPair)
}

// ProbeSelector - This selector is used to unconditionally select a probe by its identification pair and validate
// that it is activated
type ProbeSelector struct {
	ProbeIdentificationPair
}

// GetProbesIdentificationPairList - Returns the list of probes that this selector activates
func (ps *ProbeSelector) GetProbesIdentificationPairList() []ProbeIdentificationPair {
	return []ProbeIdentificationPair{ps.ProbeIdentificationPair}
}

// RunValidator - Ensures that the probes that were successfully activated follow the selector goal.
// For example, see OneOf.
func (ps *ProbeSelector) RunValidator(manager *Manager) error {
	p, ok := manager.GetProbe(ps.ProbeIdentificationPair)
	if !ok {
		return errors.Errorf("probe not found: %s", ps.ProbeIdentificationPair)
	}
	if !p.IsRunning() && p.Enabled {
		return errors.Wrap(p.GetLastError(), ps.ProbeIdentificationPair.String())
	}
	if !p.Enabled {
		return errors.Errorf(
			"%s: is disabled, add it to the activation list and check that it was not explicitly excluded by the manager options",
			ps.ProbeIdentificationPair.String())
	}
	return nil
}

// EditProbeIdentificationPair - Changes all the selectors looking for the old ProbeIdentificationPair so that they
// mow select the new one
func (ps *ProbeSelector) EditProbeIdentificationPair(old ProbeIdentificationPair, new ProbeIdentificationPair) {
	if ps.Matches(old) {
		ps.ProbeIdentificationPair = new
	}
}

// Options - Options of a Manager. These options define how a manager should be initialized.
type Options struct {
	// ActivatedProbes - List of the probes that should be activated, identified by their identification string.
	// If the list is empty, all probes will be activated.
	ActivatedProbes []ProbesSelector

	// ExcludedSections - A list of sections that should not even be verified. This list overrides the ActivatedProbes
	// list: since the excluded sections aren't loaded in the kernel, all the probes using those sections will be
	// deactivated.
	ExcludedSections []string

	// ConstantsEditor - Post-compilation constant edition. See ConstantEditor for more.
	ConstantEditors []ConstantEditor

	// MapSpecEditor - Pre-loading MapSpec editors.
	MapSpecEditors map[string]MapSpecEditor

	// VerifierOptions - Defines the log level of the verifier and the size of its log buffer. Set to 0 to disable
	// logging and 1 to get a verbose output of the error. Increase the buffer size if the output is truncated.
	VerifierOptions ebpf.CollectionOptions

	// MapEditors - External map editor. The provided eBPF maps will overwrite the maps of the Manager if their names
	// match.
	// This is particularly useful to share maps across Managers (and therefore across isolated eBPF programs), without
	// having to use the MapRouter indirection. However this technique only works before the eBPF programs are loaded,
	// and therefore before the Manager is started. The keys of the map are the names of the maps to edit, as defined
	// in their sections SEC("maps/[name]").
	MapEditors map[string]*ebpf.Map

	// MapRouter - External map routing. See MapRoute for more.
	MapRouter []MapRoute

	// TailCallRouter - External tail call routing. See TailCallRoute for more.
	TailCallRouter []TailCallRoute

	// SymFile - Kernel symbol file. If not provided, the default `/proc/kallsyms` will be used.
	SymFile string

	// PerfRingBufferSize - Manager-level default value for the perf ring buffers. Defaults to the size of 1 page
	// on the system. See PerfMap.PerfRingBuffer for more.
	DefaultPerfRingBufferSize int

	// Watermark - Manager-level default value for the watermarks of the perf ring buffers.
	// See PerfMap.Watermark for more.
	DefaultWatermark int

	// DefaultKProbeMaxActive - Manager-level default value for the kprobe max active parameter.
	// See Probe.MaxActive for more.
	DefaultKProbeMaxActive int

	// ProbeRetry - Defines the number of times that a probe will retry to attach / detach on error.
	DefaultProbeRetry uint

	// ProbeRetryDelay - Defines the delay to wait before a probe should retry to attach / detach on error.
	DefaultProbeRetryDelay time.Duration

	// RLimit - The maps & programs provided to the manager might exceed the maximum allowed memory lock.
	// (RLIMIT_MEMLOCK) If a limit is provided here it will be applied when the manager is initialized.
	RLimit *unix.Rlimit
}

// netlinkCacheKey - (TC classifier programs only) Key used to recover the netlink cache of an interface
type netlinkCacheKey struct {
	Ifindex int32
	Netns   uint64
}

// netlinkCacheValue - (TC classifier programs only) Netlink socket and qdisc object used to update the classifiers of
// an interface
type netlinkCacheValue struct {
	rtNetlink     *tc.Tc
	schedClsCount int
}

// Manager - Helper structure that manages multiple eBPF programs and maps
type Manager struct {
	wg             *sync.WaitGroup
	collectionSpec *ebpf.CollectionSpec
	collection     *ebpf.Collection
	options        Options
	netlinkCache   map[netlinkCacheKey]*netlinkCacheValue
	state          state
	stateLock      sync.RWMutex

	// Probes - List of probes handled by the manager
	Probes []*Probe

	// Maps - List of maps handled by the manager. PerfMaps should not be defined here, but instead in the PerfMaps
	// section
	Maps []*Map

	// PerfMaps - List of perf ring buffers handled by the manager
	PerfMaps []*PerfMap
}

// GetMap - Return a pointer to the requested eBPF map
// name: name of the map, as defined by its section SEC("maps/[name]")
func (m *Manager) GetMap(name string) (*ebpf.Map, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.collection == nil || m.state < initialized {
		return nil, false, ErrManagerNotInitialized
	}
	eBPFMap, ok := m.collection.Maps[name]
	if ok {
		return eBPFMap, true, nil
	}
	// Look in the list of maps
	for _, managerMap := range m.Maps {
		if managerMap.Name == name {
			return managerMap.array, true, nil
		}
	}
	// Look in the list of perf maps
	for _, perfMap := range m.PerfMaps {
		if perfMap.Name == name {
			return perfMap.array, true, nil
		}
	}
	return nil, false, nil
}

// GetMapSpec - Return a pointer to the requested eBPF MapSpec. This is useful when duplicating a map.
func (m *Manager) GetMapSpec(name string) (*ebpf.MapSpec, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.collectionSpec == nil || m.state < initialized {
		return nil, false, ErrManagerNotInitialized
	}
	eBPFMap, ok := m.collectionSpec.Maps[name]
	if ok {
		return eBPFMap, true, nil
	}
	// Look in the list of maps
	for _, managerMap := range m.Maps {
		if managerMap.Name == name {
			return managerMap.arraySpec, true, nil
		}
	}
	// Look in the list of perf maps
	for _, perfMap := range m.PerfMaps {
		if perfMap.Name == name {
			return perfMap.arraySpec, true, nil
		}
	}
	return nil, false, nil
}

// GetPerfMap - Select a perf map by its name
func (m *Manager) GetPerfMap(name string) (*PerfMap, bool) {
	for _, perfMap := range m.PerfMaps {
		if perfMap.Name == name {
			return perfMap, true
		}
	}
	return nil, false
}

// GetProgram - Return a pointer to the requested eBPF program
// section: section of the program, as defined by its section SEC("[section]")
// id: unique identifier given to a probe. If UID is empty, then all the programs matching the provided section are
// returned.
func (m *Manager) GetProgram(id ProbeIdentificationPair) ([]*ebpf.Program, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()

	var programs []*ebpf.Program
	if m.collection == nil || m.state < initialized {
		return nil, false, ErrManagerNotInitialized
	}
	if id.UID == "" {
		for _, probe := range m.Probes {
			if probe.Section == id.Section {
				programs = append(programs, probe.program)
			}
		}
		if len(programs) > 0 {
			return programs, true, nil
		}
		prog, ok := m.collection.Programs[id.Section]
		return []*ebpf.Program{prog}, ok, nil
	}
	for _, probe := range m.Probes {
		if probe.IdentificationPairMatches(id) {
			return []*ebpf.Program{probe.program}, true, nil
		}
	}
	return programs, false, nil
}

// GetProgramSpec - Return a pointer to the requested eBPF program spec
// section: section of the program, as defined by its section SEC("[section]")
// id: unique identifier given to a probe. If UID is empty, then the original program spec with the right section in the
// collection spec (if found) is return
func (m *Manager) GetProgramSpec(id ProbeIdentificationPair) ([]*ebpf.ProgramSpec, bool, error) {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()

	var programs []*ebpf.ProgramSpec
	if m.collectionSpec == nil || m.state < initialized {
		return nil, false, ErrManagerNotInitialized
	}
	if id.UID == "" {
		for _, probe := range m.Probes {
			if probe.Section == id.Section {
				programs = append(programs, probe.programSpec)
			}
		}
		if len(programs) > 0 {
			return programs, true, nil
		}
		prog, ok := m.collectionSpec.Programs[id.Section]
		return []*ebpf.ProgramSpec{prog}, ok, nil
	}
	for _, probe := range m.Probes {
		if probe.IdentificationPairMatches(id) {
			return []*ebpf.ProgramSpec{probe.programSpec}, true, nil
		}
	}
	return programs, false, nil
}

// GetProbe - Select a probe by its section and UID
func (m *Manager) GetProbe(id ProbeIdentificationPair) (*Probe, bool) {
	for _, managerProbe := range m.Probes {
		if managerProbe.IdentificationPairMatches(id) {
			return managerProbe, true
		}
	}
	return nil, false
}

// RenameProbeIdentificationPair - Renames a probe identification pair. This change will propagate to all the features in
// the manager that will try to select the probe by its old ProbeIdentificationPair.
func (m *Manager) RenameProbeIdentificationPair(oldID ProbeIdentificationPair, newID ProbeIdentificationPair) error {
	// sanity check: make sure the newID doesn't already exists
	for _, mProbe := range m.Probes {
		if mProbe.IdentificationPairMatches(newID) {
			return ErrIdentificationPairInUse
		}
	}
	p, ok := m.GetProbe(oldID)
	if !ok {
		return ErrSymbolNotFound
	}

	if oldID.Section != newID.Section {
		// edit the excluded sections
		for i, section := range m.options.ExcludedSections {
			if section == oldID.Section {
				m.options.ExcludedSections[i] = newID.Section
			}
		}
	}

	// edit the probe selectors
	for _, selector := range m.options.ActivatedProbes {
		selector.EditProbeIdentificationPair(oldID, newID)
	}

	// edit the probe
	p.Section = newID.Section
	p.UID = newID.UID
	return nil
}

// Init - Initialize the manager.
// elf: reader containing the eBPF bytecode
func (m *Manager) Init(elf io.ReaderAt) error {
	return m.InitWithOptions(elf, Options{})
}

// InitWithOptions - Initialize the manager.
// elf: reader containing the eBPF bytecode
// options: options provided to the manager to configure its initialization
func (m *Manager) InitWithOptions(elf io.ReaderAt, options Options) error {
	m.stateLock.Lock()
	if m.state > initialized {
		m.stateLock.Unlock()
		return ErrManagerRunning
	}

	m.wg = &sync.WaitGroup{}
	m.options = options
	m.netlinkCache = make(map[netlinkCacheKey]*netlinkCacheValue)
	if m.options.DefaultPerfRingBufferSize == 0 {
		m.options.DefaultPerfRingBufferSize = os.Getpagesize()
	}

	// perform a quick sanity check on the provided probes and maps
	if err := m.sanityCheck(); err != nil {
		m.stateLock.Unlock()
		return err
	}

	// set resource limit if requested
	if m.options.RLimit != nil {
		err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, m.options.RLimit)
		if err != nil {
			return errors.Wrap(err, "couldn't adjust RLIMIT_MEMLOCK")
		}
	}

	// Load the provided elf buffer
	var err error
	m.collectionSpec, err = ebpf.LoadCollectionSpecFromReader(elf)
	if err != nil {
		m.stateLock.Unlock()
		return err
	}

	// Remove excluded sections
	for _, excludedSection := range m.options.ExcludedSections {
		delete(m.collectionSpec.Programs, excludedSection)
	}

	// Match Maps and program specs
	if err := m.matchSpecs(); err != nil {
		m.stateLock.Unlock()
		return err
	}

	// Configure activated probes
	m.activateProbes()
	m.state = initialized
	m.stateLock.Unlock()

	// Edit program constants
	if len(options.ConstantEditors) > 0 {
		if err := m.editConstants(); err != nil {
			return err
		}
	}

	// Edit map spec
	if len(options.MapSpecEditors) > 0 {
		if err := m.editMapSpecs(); err != nil {
			return err
		}
	}

	// Edit program maps
	if len(options.MapEditors) > 0 {
		if err := m.editMaps(options.MapEditors); err != nil {
			return err
		}
	}

	// Load pinned maps and pinned programs to avoid loading them twice
	if err := m.loadPinnedObjects(); err != nil {
		return err
	}

	// Load eBPF program with the provided verifier options
	if err := m.loadCollection(); err != nil {
		return err
	}
	return nil
}

// Start - Attach eBPF programs, start perf ring readers and apply maps and tail calls routing.
func (m *Manager) Start() error {
	m.stateLock.Lock()
	if m.state < initialized {
		m.stateLock.Unlock()
		return ErrManagerNotInitialized
	}
	if m.state >= running {
		m.stateLock.Unlock()
		return nil
	}

	// clean up tracefs
	if err := m.cleanupTracefs(); err != nil {
		return errors.Wrap(err, "failed to cleanup tracefs")
	}

	// Start perf ring readers
	for _, perfRing := range m.PerfMaps {
		if err := perfRing.Start(); err != nil {
			// Clean up
			_ = m.stop(CleanInternal)
			m.stateLock.Unlock()
			return err
		}
	}

	// Attach eBPF programs
	for _, probe := range m.Probes {
		// ignore the error, they are already collected per probes and will be surfaced by the
		// activation validators if needed.
		_ = probe.Attach()
	}

	m.state = running
	m.stateLock.Unlock()

	// Check probe selectors
	var validationErrs error
	for _, selector := range m.options.ActivatedProbes {
		if err := selector.RunValidator(m); err != nil {
			validationErrs = multierror.Append(validationErrs, err)
		}
	}
	if validationErrs != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return errors.Wrap(validationErrs, "probes activation validation failed")
	}

	// Handle Maps router
	if err := m.UpdateMapRoutes(m.options.MapRouter...); err != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return err
	}

	// Handle Program router
	if err := m.UpdateTailCallRoutes(m.options.TailCallRouter...); err != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return err
	}
	return nil
}

// Stop - Detach all eBPF programs and stop perf ring readers. The cleanup parameter defines which maps should be closed.
// See MapCleanupType for mode.
func (m *Manager) Stop(cleanup MapCleanupType) error {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.state < initialized {
		return ErrManagerNotInitialized
	}
	return m.stop(cleanup)
}

func (m *Manager) stop(cleanup MapCleanupType) error {
	var err error

	// Stop perf ring readers
	for _, perfRing := range m.PerfMaps {
		err = ConcatErrors(
			err,
			errors.Wrapf(perfRing.Stop(cleanup), "perf ring reader %s couldn't gracefully shut down", perfRing.Name),
		)
	}

	// Detach eBPF programs
	for _, probe := range m.Probes {
		err = ConcatErrors(
			err,
			errors.Wrapf(probe.Stop(), "program %s couldn't gracefully shut down", probe.Section),
		)
	}

	// Close maps
	for _, managerMap := range m.Maps {
		err = ConcatErrors(
			err,
			errors.Wrapf(managerMap.Close(cleanup), "couldn't gracefully close map %s", managerMap.Name),
		)
	}

	// Close all netlink sockets
	for _, entry := range m.netlinkCache {
		err = ConcatErrors(err, entry.rtNetlink.Close())
	}

	// Clean up collection
	// Note: we might end up closing the same programs and maps multiple times but the library gracefully handles those
	// situations. We can't only rely on the collection to close all maps and programs because some pinned objects were
	// removed from the collection.
	m.collection.Close()

	// Wait for all go routines to stop
	m.wg.Wait()
	m.state = reset
	return err
}

// NewMap - Create a new map using the provided parameters. The map is added to the list of maps managed by the manager.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) NewMap(spec ebpf.MapSpec, options MapOptions) (*ebpf.Map, error) {
	// check if the name of the new map is available
	_, exists, _ := m.GetMap(spec.Name)
	if exists {
		return nil, ErrMapNameInUse
	}

	// Create the new map
	managerMap, err := loadNewMap(spec, options)
	if err != nil {
		return nil, err
	}

	// Init map
	if err := managerMap.Init(m); err != nil {
		// Clean up
		_ = managerMap.Close(CleanInternal)
		return nil, err
	}

	// Add map to the list of maps managed by the manager
	m.Maps = append(m.Maps, managerMap)
	return managerMap.array, nil
}

// CloneMap - Duplicates the spec of an existing map, before creating a new one.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) CloneMap(name string, newName string, options MapOptions) (*ebpf.Map, error) {
	// Select map to clone
	oldSpec, exists, err := m.GetMapSpec(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.Wrapf(ErrUnknownSection, "failed to clone maps/%s", name)
	}

	// Duplicate spec and create a new map
	spec := oldSpec.Copy()
	spec.Name = newName
	return m.NewMap(*spec, options)
}

// NewPerfRing - Creates a new perf ring and start listening for events.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) NewPerfRing(spec ebpf.MapSpec, options MapOptions, perfMapOptions PerfMapOptions) (*ebpf.Map, error) {
	// check if the name of the new map is available
	_, exists, _ := m.GetMap(spec.Name)
	if exists {
		return nil, ErrMapNameInUse
	}

	// Create new map and perf ring buffer reader
	perfMap, err := loadNewPerfMap(spec, options, perfMapOptions)
	if err != nil {
		return nil, err
	}

	// Setup perf buffer reader
	if err := perfMap.Init(m); err != nil {
		return nil, err
	}

	// Start perf buffer reader
	if err := perfMap.Start(); err != nil {
		// clean up
		_ = perfMap.Stop(CleanInternal)
		return nil, err
	}

	// Add map to the list of perf ring managed by the manager
	m.PerfMaps = append(m.PerfMaps, perfMap)
	return perfMap.array, nil
}

// ClonePerfRing - Clone an existing perf map and create a new one with the same spec.
// Use a MapRoute to make this map available to the programs of the manager.
func (m *Manager) ClonePerfRing(name string, newName string, options MapOptions, perfMapOptions PerfMapOptions) (*ebpf.Map, error) {
	// Select map to clone
	oldSpec, exists, err := m.GetMapSpec(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.Wrapf(ErrUnknownSection, "failed to clone maps/%s: couldn't find map", name)
	}

	// Duplicate spec and create a new map
	spec := oldSpec.Copy()
	spec.Name = newName
	return m.NewPerfRing(*spec, options, perfMapOptions)
}

// AddHook - Hook an existing program to a hook point. This is particularly useful when you need to trigger an
// existing program on a hook point that is determined at runtime. For example, you might want to hook an existing
// eBPF TC classifier to the newly created interface of a container. Make sure to specify a unique uid in the new probe,
// you will need it if you want to detach the program later. The original program is selected using the provided UID and
// the section provided in the new probe.
func (m *Manager) AddHook(UID string, newProbe Probe) error {
	oldID := ProbeIdentificationPair{UID, newProbe.Section}
	// Look for the eBPF program
	progs, found, err := m.GetProgram(oldID)
	if err != nil {
		return err
	}
	if !found || len(progs) == 0 {
		return errors.Wrapf(ErrUnknownSection, "couldn't find program %v", oldID)
	}
	prog := progs[0]
	progSpecs, found, _ := m.GetProgramSpec(oldID)
	if !found || len(progSpecs) == 0 {
		return errors.Wrapf(ErrUnknownSection, "couldn't find programSpec %v", oldID)
	}
	progSpec := progSpecs[0]

	// Ensure that the new probe is enabled
	newProbe.Enabled = true

	// Make sure the provided identification pair is unique
	_, exists, _ := m.GetProgramSpec(newProbe.GetIdentificationPair())
	if exists {
		return errors.Wrapf(ErrIdentificationPairInUse, "couldn't add probe %v", newProbe.GetIdentificationPair())
	}

	// Clone program
	clonedProg, err := prog.Clone()
	if err != nil {
		return errors.Wrapf(err, "couldn't clone %v", oldID)
	}
	newProbe.program = clonedProg
	newProbe.programSpec = progSpec

	// Init program
	if err = newProbe.Init(m); err != nil {
		// clean up
		_ = newProbe.Stop()
		return errors.Wrap(err, "failed to initialize new probe")
	}

	// Pin if needed
	if newProbe.PinPath != "" {
		if err = newProbe.program.Pin(newProbe.PinPath); err != nil {
			// clean up
			_ = newProbe.Stop()
			return errors.Wrap(err, "couldn't pin new probe")
		}
	}

	// Attach program
	if err = newProbe.Attach(); err != nil {
		// clean up
		_ = newProbe.Stop()
		return errors.Wrapf(err, "couldn't attach new probe")
	}

	// Add probe to the list of probes
	m.Probes = append(m.Probes, &newProbe)
	return nil
}

// DetachHook - Detach an eBPF program from a hook point. If there is only one instance left of this program in the
// kernel, then the probe will be detached but the program will not be closed (so that it can be used later). In that
// case, calling DetachHook has essentially the same effect as calling Detach() on the right Probe instance. However,
// if there are more than one instance in the kernel of the requested program, then the probe selected by (section, UID)
// is detached, and its own version of the program is closed.
func (m *Manager) DetachHook(section string, UID string) error {
	oldID := ProbeIdentificationPair{UID, section}
	// Check how many instances of the program are left in the kernel
	progs, _, err := m.GetProgram(ProbeIdentificationPair{"", section})
	if err != nil {
		return err
	}
	shouldStop := len(progs) > 1

	// Look for the probe
	idToDelete := -1
	for id, managerProbe := range m.Probes {
		if managerProbe.IdentificationPairMatches(oldID) {
			// Detach or stop the probe depending on shouldStop
			if shouldStop {
				if err = managerProbe.Stop(); err != nil {
					return errors.Wrapf(err, "couldn't stop probe %v", oldID)
				}
			} else {
				if err = managerProbe.Detach(); err != nil {
					return errors.Wrapf(err, "couldn't detach probe %v", oldID)
				}
			}
			idToDelete = id
		}
	}
	if idToDelete >= 0 {
		m.Probes = append(m.Probes[:idToDelete], m.Probes[idToDelete+1:]...)
	}
	return nil
}

// CloneProgram - Create a clone of a program, load it in the kernel and attach it to its hook point. Since the eBPF
// program instructions are copied before the program is loaded, you can edit them with a ConstantEditor, or remap
// the eBPF maps as you like. This is particularly useful to workaround the absence of Array of Maps and Hash of Maps:
// first create the new maps you need, then clone the program you're interested in and rewrite it with the new maps,
// using a MapEditor. The original program is selected using the provided UID and the section provided in the new probe.
// Note that the BTF based constant edition will note work with this method.
func (m *Manager) CloneProgram(UID string, newProbe Probe, constantsEditors []ConstantEditor, mapEditors map[string]*ebpf.Map) error {
	oldID := ProbeIdentificationPair{UID, newProbe.Section}
	// Find the program specs
	progSpecs, found, err := m.GetProgramSpec(oldID)
	if err != nil {
		return err
	}
	if !found || len(progSpecs) == 0 {
		return errors.Wrapf(ErrUnknownSection, "couldn't find programSpec %v", oldID)
	}
	progSpec := progSpecs[0]

	// Check if the new probe has a unique identification pair
	_, exists, _ := m.GetProgram(newProbe.GetIdentificationPair())
	if exists {
		return errors.Wrapf(ErrIdentificationPairInUse, "couldn't add probe %v", newProbe.GetIdentificationPair())
	}

	// Make sure the new probe is activated
	newProbe.Enabled = true

	// Clone the program
	clonedSpec := progSpec.Copy()
	newProbe.programSpec = clonedSpec

	// Edit constants
	for _, editor := range constantsEditors {
		if err := m.editConstant(newProbe.programSpec, editor); err != nil {
			return errors.Wrapf(err, "couldn't edit constant %s", editor.Name)
		}
	}

	// Write current maps
	if err = m.rewriteMaps(newProbe.programSpec, m.collection.Maps); err != nil {
		return errors.Wrapf(err, "couldn't rewrite maps in %v", newProbe.GetIdentificationPair())
	}

	// Rewrite with new maps
	if err = m.rewriteMaps(newProbe.programSpec, mapEditors); err != nil {
		return errors.Wrapf(err, "couldn't rewrite maps in %v", newProbe.GetIdentificationPair())
	}

	// Init
	if err = newProbe.InitWithOptions(m, true, true); err != nil {
		// clean up
		_ = newProbe.Stop()
		return errors.Wrapf(err, "failed to initialize new probe %v", newProbe.GetIdentificationPair())
	}

	// Attach new program
	if err = newProbe.Attach(); err != nil {
		// clean up
		_ = newProbe.Stop()
		return errors.Wrapf(err, "failed to attach new probe %v", newProbe.GetIdentificationPair())
	}

	// Add probe to the list of probes
	m.Probes = append(m.Probes, &newProbe)
	return nil
}

// UpdateMapRoutes - Update one or multiple map of maps structures so that the provided keys point to the provided maps.
func (m *Manager) UpdateMapRoutes(router ...MapRoute) error {
	for _, route := range router {
		if err := m.updateMapRoute(route); err != nil {
			return err
		}
	}
	return nil
}

// updateMapRoute - Update a map of maps structure so that the provided key points to the provided map
func (m *Manager) updateMapRoute(route MapRoute) error {
	// Select the routing map
	routingMap, found, err := m.GetMap(route.RoutingMapName)
	if err != nil {
		return err
	}
	if !found {
		return errors.Wrapf(ErrUnknownSection, "couldn't find routing map %s", route.RoutingMapName)
	}

	// Get file descriptor of the routed map
	var fd uint32
	if route.Map != nil {
		fd = uint32(route.Map.FD())
	} else {
		routedMap, found, err := m.GetMap(route.RoutedName)
		if err != nil {
			return err
		}
		if !found {
			return errors.Wrapf(ErrUnknownSection, "couldn't find routed map %s", route.RoutedName)
		}
		fd = uint32(routedMap.FD())
	}

	// Insert map
	if err = routingMap.Put(route.Key, fd); err != nil {
		return errors.Wrapf(err, "couldn't update routing map %s", route.RoutingMapName)
	}
	return nil
}

// UpdateTailCallRoutes - Update one or multiple program arrays so that the provided keys point to the provided programs.
func (m *Manager) UpdateTailCallRoutes(router ...TailCallRoute) error {
	for _, route := range router {
		if err := m.updateTailCallRoute(route); err != nil {
			return err
		}
	}
	return nil
}

// updateTailCallRoute - Update a program array so that the provided key point to the provided program.
func (m *Manager) updateTailCallRoute(route TailCallRoute) error {
	// Select the routing map
	routingMap, found, err := m.GetMap(route.ProgArrayName)
	if err != nil {
		return err
	}
	if !found {
		return errors.Wrapf(ErrUnknownSection, "couldn't find routing map %s", route.ProgArrayName)
	}

	// Get file descriptor of the routed program
	var fd uint32
	if route.Program != nil {
		fd = uint32(route.Program.FD())
	} else {
		progs, found, err := m.GetProgram(route.ProbeIdentificationPair)
		if err != nil {
			return err
		}
		if !found || len(progs) == 0 {
			return errors.Wrapf(ErrUnknownSection, "couldn't find program %v", route.ProbeIdentificationPair)
		}
		fd = uint32(progs[0].FD())
	}

	// Insert tail call
	if err = routingMap.Put(route.Key, fd); err != nil {
		return errors.Wrapf(err, "couldn't update routing map %s", route.ProgArrayName)
	}
	return nil
}

func (m *Manager) getProbeProgramSpec(section string) (*ebpf.ProgramSpec, error) {
	spec, ok := m.collectionSpec.Programs[section]
	if !ok {
		// Check if the probe section is in the list of excluded sections
		var excluded bool
		for _, excludedSection := range m.options.ExcludedSections {
			if excludedSection == section {
				excluded = true
				break
			}
		}
		if !excluded {
			return nil, errors.Wrapf(ErrUnknownSection, "couldn't find program at %s", section)
		}
	}
	return spec, nil
}

// matchSpecs - Match loaded maps and program specs with the maps and programs provided to the manager
func (m *Manager) matchSpecs() error {
	// Match programs
	for _, probe := range m.Probes {
		programSpec, err := m.getProbeProgramSpec(probe.Section)
		if err != nil {
			return err
		}
		if !probe.CopyProgram {
			probe.programSpec = programSpec
		} else {
			probe.programSpec = programSpec.Copy()
			m.collectionSpec.Programs[probe.Section + probe.UID] = probe.programSpec
		}
	}

	// Match maps
	for _, managerMap := range m.Maps {
		spec, ok := m.collectionSpec.Maps[managerMap.Name]
		if !ok {
			return errors.Wrapf(ErrUnknownSection, "couldn't find map at maps/%s", managerMap.Name)
		}
		spec.Contents = managerMap.Contents
		spec.Freeze = managerMap.Freeze
		managerMap.arraySpec = spec
	}

	// Match perfmaps
	for _, perfMap := range m.PerfMaps {
		spec, ok := m.collectionSpec.Maps[perfMap.Name]
		if !ok {
			return errors.Wrapf(ErrUnknownSection, "couldn't find map at maps/%s", perfMap.Name)
		}
		perfMap.arraySpec = spec
	}
	return nil
}

func (m *Manager) activateProbes() {
	shouldPopulateActivatedProbes := len(m.options.ActivatedProbes) == 0
	for _, mProbe := range m.Probes {
		shouldActivate := shouldPopulateActivatedProbes
		for _, selector := range m.options.ActivatedProbes {
			for _, p := range selector.GetProbesIdentificationPairList() {
				if mProbe.IdentificationPairMatches(p) {
					shouldActivate = true
				}
			}
		}
		for _, p := range m.options.ExcludedSections {
			if mProbe.Section == p {
				shouldActivate = false
			}
		}
		mProbe.Enabled = shouldActivate

		if shouldPopulateActivatedProbes {
			// this will ensure that we check that everything has been activated by default when no selectors are provided
			m.options.ActivatedProbes = append(m.options.ActivatedProbes, &ProbeSelector{
				ProbeIdentificationPair: mProbe.GetIdentificationPair(),
			})
		}
	}
}

// UpdateActivatedProbes - update the list of activated probes
func (m *Manager) UpdateActivatedProbes(selectors []ProbesSelector) error {
	currentProbes := make(map[ProbeIdentificationPair]*Probe)
	for _, p := range m.Probes {
		if p.Enabled {
			currentProbes[p.GetIdentificationPair()] = p
		}
	}

	nextProbes := make(map[ProbeIdentificationPair]bool)
	for _, selector := range selectors {
		for _, id := range selector.GetProbesIdentificationPairList() {
			nextProbes[id] = true
		}
	}

	for id, _ := range nextProbes {
		if _, alreadyPresent := currentProbes[id]; alreadyPresent {
			delete(currentProbes, id)
		} else {
			probe, _ := m.GetProbe(id)
			probe.Enabled = true
			if err := probe.Init(m); err != nil {
				return err
			}
			if err := probe.Attach(); err != nil {
				return err
			}
		}
	}

	for _, probe := range currentProbes {
		if err := probe.Detach(); err != nil {
			return err
		}
		probe.Enabled = false
	}

	// update activated probes & check activation
	m.options.ActivatedProbes = selectors
	var validationErrs error
	for _, selector := range m.options.ActivatedProbes {
		if err := selector.RunValidator(m); err != nil {
			validationErrs = multierror.Append(validationErrs, err)
		}
	}

	if validationErrs != nil {
		// Clean up
		_ = m.Stop(CleanInternal)
		return errors.Wrap(validationErrs, "probes activation validation failed")
	}

	return nil
}

// editConstants - Edit the programs in the CollectionSpec with the provided constant editors. Tries with the BTF global
// variable first, and fall back to the asm method if BTF is not available.
func (m *Manager) editConstants() error {
	// Start with the BTF based solution
	rodata := m.collectionSpec.Maps[".rodata"]
	if rodata != nil && rodata.BTF != nil {
		consts := map[string]interface{}{}
		for _, editor := range m.options.ConstantEditors {
			consts[editor.Name] = editor.Value
		}
		return m.collectionSpec.RewriteConstants(consts)
	}

	// Fall back to the old school constant edition
	for _, constantEditor := range m.options.ConstantEditors {

		// Edit the constant of the provided programs
		for _, id := range constantEditor.ProbeIdentificationPairs {
			programs, found, err := m.GetProgramSpec(id)
			if err != nil {
				return err
			}
			if !found || len(programs) == 0 {
				return errors.Wrapf(ErrUnknownSection, "couldn't find programSpec %v", id)
			}
			prog := programs[0]

			// Edit program
			if err := m.editConstant(prog, constantEditor); err != nil {
				return errors.Wrapf(err, "couldn't edit %s in %v", constantEditor.Name, id)
			}
		}

		// Apply to all programs if no section was provided
		if len(constantEditor.ProbeIdentificationPairs) == 0 {
			for section, prog := range m.collectionSpec.Programs {
				if err := m.editConstant(prog, constantEditor); err != nil {
					return errors.Wrapf(err, "couldn't edit %s in %s", constantEditor.Name, section)
				}
			}
		}
	}
	return nil
}

// editMapSpecs - Update the MapSpec with the provided MapSpec editors.
func (m *Manager) editMapSpecs() error {
	for name, mapEditor := range m.options.MapSpecEditors {
		// select the map spec
		spec, exists, err := m.GetMapSpec(name)
		if err != nil {
			return err
		}
		if !exists {
			return errors.Wrapf(ErrUnknownSection, "failed to edit maps/%s: couldn't find map", name)
		}
		if EditType&mapEditor.EditorFlag == EditType {
			spec.Type = mapEditor.Type
		}
		if EditMaxEntries&mapEditor.EditorFlag == EditMaxEntries {
			spec.MaxEntries = mapEditor.MaxEntries
		}
		if EditFlags&mapEditor.EditorFlag == EditFlags {
			spec.Flags = mapEditor.Flags
		}
	}
	return nil
}

// editConstant - Edit the provided program with the provided constant using the asm method.
func (m *Manager) editConstant(prog *ebpf.ProgramSpec, editor ConstantEditor) error {
	edit := Edit(&prog.Instructions)
	data, ok := (editor.Value).(uint64)
	if !ok {
		return fmt.Errorf("with the asm method, the constant value has to be of type uint64")
	}
	if err := edit.RewriteConstant(editor.Name, data); err != nil {
		if IsUnreferencedSymbol(err) && editor.FailOnMissing {
			return err
		}
	}
	return nil
}

// rewriteMaps - Rewrite the provided program spec with the provided maps
func (m *Manager) rewriteMaps(program *ebpf.ProgramSpec, eBPFMaps map[string]*ebpf.Map) error {
	for symbol, eBPFMap := range eBPFMaps {
		fd := eBPFMap.FD()
		err := program.Instructions.RewriteMapPtr(symbol, fd)
		if err != nil {
			return errors.Wrapf(err, "couldn't rewrite map %s", symbol)
		}
	}
	return nil
}

// editMaps - RewriteMaps replaces all references to specific maps.
func (m *Manager) editMaps(maps map[string]*ebpf.Map) error {
	// Rewrite maps
	if err := m.collectionSpec.RewriteMaps(maps); err != nil {
		return err
	}

	// The rewrite operation removed the original maps from the CollectionSpec and will therefore not appear in the
	// Collection, make the mapping with the Manager.Maps now
	found := false
	for name, rwMap := range maps {
		for _, managerMap := range m.Maps {
			if managerMap.Name == name {
				managerMap.array = rwMap
				managerMap.externalMap = true
				managerMap.editedMap = true
				found = true
			}
		}
		for _, perfRing := range m.PerfMaps {
			if perfRing.Name == name {
				perfRing.array = rwMap
				perfRing.externalMap = true
				perfRing.editedMap = true
				found = true
			}
		}
		if !found {
			// Create a new entry
			m.Maps = append(m.Maps, &Map{
				array:       rwMap,
				manager:     m,
				externalMap: true,
				editedMap:   true,
				Name:        name,
			})
		}
	}
	return nil
}

// loadCollection - Load the eBPF maps and programs in the CollectionSpec. Programs and Maps are pinned when requested.
func (m *Manager) loadCollection() error {
	var err error
	// Load collection
	m.collection, err = ebpf.NewCollectionWithOptions(m.collectionSpec, m.options.VerifierOptions)
	if err != nil {
		return errors.Wrap(err, "couldn't load eBPF programs")
	}

	// Initialize Maps
	for _, managerMap := range m.Maps {
		if err := managerMap.Init(m); err != nil {
			return err
		}
	}

	// Initialize PerfMaps
	for _, perfMap := range m.PerfMaps {
		if err := perfMap.Init(m); err != nil {
			return err
		}
	}

	// Initialize Probes
	for _, probe := range m.Probes {
		// Find program
		if err := probe.Init(m); err != nil {
			return err
		}
	}
	return nil
}

// loadPinnedObjects - Loads pinned programs and maps from the bpf virtual file system. If a map is found, the
// CollectionSpec will be edited so that references to that map point to the pinned one. If a program is found, it will
// be detached from the CollectionSpec to avoid loading it twice.
func (m *Manager) loadPinnedObjects() error {
	// Look for pinned maps
	for _, managerMap := range m.Maps {
		if managerMap.PinPath == "" {
			continue
		}
		if err := m.loadPinnedMap(managerMap); err != nil {
			if err == ErrPinnedObjectNotFound {
				continue
			}
			return err
		}
	}

	// Look for pinned perf buffer
	for _, perfMap := range m.PerfMaps {
		if perfMap.PinPath == "" {
			continue
		}
		if err := m.loadPinnedMap(&perfMap.Map); err != nil {
			if err == ErrPinnedObjectNotFound {
				continue
			}
			return err
		}
	}

	// Look for pinned programs
	for _, prog := range m.Probes {
		if prog.PinPath == "" {
			continue
		}
		if err := m.loadPinnedProgram(prog); err != nil {
			if err == ErrPinnedObjectNotFound {
				continue
			}
			return err
		}
	}
	return nil
}

// loadPinnedMap - Loads a pinned map
func (m *Manager) loadPinnedMap(managerMap *Map) error {
	// Check if the pinned object exists
	if _, err := os.Stat(managerMap.PinPath); err != nil {
		return ErrPinnedObjectNotFound
	}

	// To maximize kernel compatibility, build the expected MapABI structure
	abi := ebpf.MapABI{
		Type:       managerMap.arraySpec.Type,
		KeySize:    managerMap.arraySpec.KeySize,
		ValueSize:  managerMap.arraySpec.ValueSize,
		MaxEntries: managerMap.arraySpec.MaxEntries,
		Flags:      managerMap.arraySpec.Flags,
	}
	pinnedMap, err := ebpf.LoadPinnedMapExplicit(managerMap.PinPath, &abi)
	if err != nil {
		return errors.Wrapf(err, "couldn't load map %s from %s", managerMap.Name, managerMap.PinPath)
	}

	// Replace map in CollectionSpec
	if err := m.editMaps(map[string]*ebpf.Map{managerMap.Name: pinnedMap}); err != nil {
		return err
	}
	managerMap.array = pinnedMap
	managerMap.externalMap = true
	return nil
}

// loadPinnedProgram - Loads a pinned program
func (m *Manager) loadPinnedProgram(prog *Probe) error {
	// Check if the pinned object exists
	if _, err := os.Stat(prog.PinPath); err != nil {
		return ErrPinnedObjectNotFound
	}

	// To maximize kernel compatibility, build the expected ProgramABI structure
	abi := ebpf.ProgramABI{
		Type: prog.programSpec.Type,
	}
	pinnedProg, err := ebpf.LoadPinnedProgramExplicit(prog.PinPath, &abi)
	if err != nil {
		return errors.Wrapf(err, "couldn't load program %v from %s", prog.GetIdentificationPair(), prog.PinPath)
	}
	prog.program = pinnedProg

	// Detach program from CollectionSpec
	delete(m.collectionSpec.Programs, prog.Section)
	return nil
}

// sanityCheck - Checks that the probes and maps of the manager were properly defined
func (m *Manager) sanityCheck() error {
	// Check if map names are unique
	cache := map[string]bool{}
	for _, managerMap := range m.Maps {
		_, ok := cache[managerMap.Name]
		if ok {
			return errors.Wrapf(ErrMapNameInUse, "map %s failed the sanity check", managerMap.Name)
		}
		cache[managerMap.Name] = true
	}
	for _, perfMap := range m.PerfMaps {
		_, ok := cache[perfMap.Name]
		if ok {
			return errors.Wrapf(ErrMapNameInUse, "map %s failed the sanity check", perfMap.Name)
		}
		cache[perfMap.Name] = true
	}

	// Check if probes identification pairs are unique, request the usage of CloneProbe otherwise
	cache = map[string]bool{}
	for _, managerProbe := range m.Probes {
		_, ok := cache[managerProbe.GetIdentificationPair().String()]
		if ok {
			return errors.Wrapf(ErrCloneProbeRequired, "%v failed the sanity check", managerProbe.GetIdentificationPair())
		}
		cache[managerProbe.GetIdentificationPair().String()] = true
	}
	return nil
}

// newNetlinkConnection - (TC classifier) TC classifiers are attached by creating a qdisc on the requested
// interface. A netlink socket is required to create a qdisc. Since this socket can be re-used for multiple classifiers,
// instantiate the connection at the manager level and cache the netlink socket.
func (m *Manager) newNetlinkConnection(ifindex int32, netns uint64) (*netlinkCacheValue, error) {
	var cacheEntry netlinkCacheValue
	var err error
	// Open a netlink socket for the requested namespace
	cacheEntry.rtNetlink, err = tc.Open(&tc.Config{
		NetNS: int(netns),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "couldn't open a NETLink socket in namespace %v", netns)
	}

	// Insert in manager cache
	m.netlinkCache[netlinkCacheKey{Ifindex: ifindex, Netns: netns}] = &cacheEntry
	return &cacheEntry, nil
}

type procMask uint8

const (
	Running procMask = iota
	Exited
)

// cleanupKprobeEvents - Cleans up kprobe_events and uprobe_events by removing entries of known UIDs, that are not used
// anymore.
//
// Previous instances of this manager might have been killed unexpectedly. When this happens,
// kprobe_events is not cleaned up properly and can grow indefinitely until it reaches 65k
// entries (see: https://elixir.bootlin.com/linux/latest/source/kernel/trace/trace_output.c#L696)
// Once the limit is reached, the kernel refuses to load new probes and throws a "no such device"
// error. To prevent this, start by cleaning up the kprobe_events entries of previous managers that
// are not running anymore.
func (m *Manager) cleanupTracefs() error {
	// build the pattern to look for in kprobe_events and uprobe_events
	var uidSet []string
	for _, p := range m.Probes {
		if len(p.UID) == 0 {
			continue
		}
		
		var found bool
		for _, uid := range uidSet {
			if uid == p.UID {
				found = true
				break
			}
		}
		if !found {
			uidSet = append(uidSet, p.UID)
		}
	}
	pattern, err := regexp.Compile(fmt.Sprintf(`(p|r)[0-9]*:(kprobes|uprobes)/(.*(%s)_([0-9]*)) .*`, strings.Join(uidSet, "|")))
	if err != nil {
		return errors.Wrap(err, "pattern generation failed")
	}

	// clean up kprobe_events
	var cleanUpErrors *multierror.Error
	pidMask := make(map[int]procMask)
	cleanUpErrors = multierror.Append(cleanUpErrors, cleanupKprobeEvents(pattern, pidMask))
	cleanUpErrors = multierror.Append(cleanUpErrors, cleanupUprobeEvents(pattern, pidMask))
	if cleanUpErrors.Len() == 0 {
		return nil
	}
	return cleanUpErrors
}

func cleanupKprobeEvents(pattern *regexp.Regexp, pidMask map[int]procMask) error {
	kprobeEvents, err := ReadKprobeEvents()
	if err != nil {
		return errors.Wrap(err, "couldn't read kprobe_events")
	}
	var cleanUpErrors error
	for _, match := range pattern.FindAllStringSubmatch(kprobeEvents, -1) {
		if len(match) < 6 {
			continue
		}

		// check if the provided pid still exists
		pid, err := strconv.Atoi(match[5])
		if err != nil {
			continue
		}
		if state, ok := pidMask[pid]; !ok {
			// this short sleep is used to avoid a CPU spike (5s ~ 60k * 80 microseconds)
			time.Sleep(80*time.Microsecond)

			_, err = process.NewProcess(int32(pid))
			if err == nil {
				// the process is still running, continue
				pidMask[pid] = Running
				continue
			} else {
				pidMask[pid] = Exited
			}
		} else {
			if state == Running {
				// the process is still running, continue
				continue
			}
		}

		// remove the entry
		cleanUpErrors = multierror.Append(cleanUpErrors, disableKprobeEvent(match[3]))
	}
	return cleanUpErrors
}

func cleanupUprobeEvents(pattern *regexp.Regexp, pidMask map[int]procMask) error {
	uprobeEvents, err := ReadUprobeEvents()
	if err != nil {
		return errors.Wrap(err, "couldn't read uprobe_events")
	}
	var cleanUpErrors error
	for _, match := range pattern.FindAllStringSubmatch(uprobeEvents, -1) {
		if len(match) < 6 {
			continue
		}

		// check if the provided pid still exists
		pid, err := strconv.Atoi(match[5])
		if err != nil {
			continue
		}
		if state, ok := pidMask[pid]; !ok {
			// this short sleep is used to avoid a CPU spike (5s ~ 60k * 80 microseconds)
			time.Sleep(80*time.Microsecond)

			_, err = process.NewProcess(int32(pid))
			if err == nil {
				// the process is still running, continue
				pidMask[pid] = Running
				continue
			} else {
				pidMask[pid] = Exited
			}
		} else {
			if state == Running {
				// the process is still running, continue
				continue
			}
		}

		// remove the entry
		cleanUpErrors = multierror.Append(cleanUpErrors, disableUprobeEvent(match[3]))
	}
	return cleanUpErrors
}
