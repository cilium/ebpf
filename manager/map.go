package manager

import (
	"github.com/pkg/errors"
	"os"

	"github.com/DataDog/ebpf"
)

// MapCleanupType - The map clean up type defines how the maps of a manager should be cleaned up on exit.
//
// We call "external" a map that wasn't loaded by the current manager. Those maps can end up being used by the
// current manager through 2 different ways: either because they were pinned or because they were edited into the
// programs of the manager before they were loaded. However those maps might still be used by other managers out there,
// even after the current one closes.
//
// A map can only be in one of the following categories
//
//               ----------------------         ---------------------------------------
//              |   Internally loaded  |       |           Externally loaded           |
//               ----------------------         ---------------------------------------
//  Categories: |  Pinned | Not Pinned |       |  Pinned | Pinned and Edited  | Edited |
//               ----------------------         ---------------------------------------
//
type MapCleanupType int

const (
	CleanInternalPinned          MapCleanupType = 1 << 1
	CleanInternalNotPinned       MapCleanupType = 1 << 2
	CleanExternalPinned          MapCleanupType = 1 << 3
	CleanExternalPinnedAndEdited MapCleanupType = 1 << 4
	CleanExternalEdited          MapCleanupType = 1 << 5
	CleanInternal                MapCleanupType = CleanInternalPinned | CleanInternalNotPinned
	CleanExternal                MapCleanupType = CleanExternalPinned | CleanExternalPinnedAndEdited | CleanExternalEdited
	CleanAll                     MapCleanupType = CleanInternal | CleanExternal
)

// MapOptions - Generic Map options that are not shared with the MapSpec definition
type MapOptions struct {
	// PinPath - Once loaded, the eBPF map will be pinned to this path. If the map has already been pinned and is
	// already present in the kernel, then it will be loaded from this path.
	PinPath string

	// AlwaysCleanup - Overrides the clean up type given to the manager. See CleanupType for more.
	AlwaysCleanup bool
}

type Map struct {
	array     *ebpf.Map
	arraySpec *ebpf.MapSpec
	manager   *Manager

	// externalMap - Indicates if the underlying eBPF map came from the current Manager or was loaded from an external
	// source (=> pinned maps or rewritten maps)
	externalMap bool
	// editedMap - Indicates that the map was edited at runtime
	editedMap bool

	// Name - Name of the map as defined in its section SEC("maps/[name]")
	Name string

	// Contents - The initial contents of the map. May be nil.
	Contents []ebpf.MapKV

	// Freeze - Whether to freeze a map after setting its initial contents.
	Freeze bool

	// Other options
	MapOptions
}

// loadNewMap - Creates a new map instance, load it and return a pointer to the Map structure
func loadNewMap(spec ebpf.MapSpec, options MapOptions) (*Map, error) {
	// Create new map
	managerMap := Map{
		arraySpec:  &spec,
		Name:       spec.Name,
		Contents:   spec.Contents,
		Freeze:     spec.Freeze,
		MapOptions: options,
	}

	// Load map
	var err error
	if managerMap.array, err = ebpf.NewMap(&spec); err != nil {
		return nil, err
	}

	// Pin map if need be
	if managerMap.PinPath != "" {
		if err := managerMap.array.Pin(managerMap.PinPath); err != nil {
			return nil, errors.Wrapf(err, "couldn't pin map %s at %s", managerMap.Name, managerMap.PinPath)
		}
	}
	return &managerMap, nil
}

// Init - Initialize a map
func (m *Map) Init(manager *Manager) error {
	m.manager = manager
	// Look for the loaded Map if it isn't already set
	if m.array == nil {
		array, ok := manager.collection.Maps[m.Name]
		if !ok {
			return errors.Wrapf(ErrUnknownSection, "couldn't find map at maps/%s", m.Name)
		}
		m.array = array

		// Pin map if needed
		if m.PinPath != "" {
			if err := m.array.Pin(m.PinPath); err != nil {
				return errors.Wrapf(err, "couldn't pin map %s at %s", m.Name, m.PinPath)
			}
		}
	}
	return nil
}

// Close - Close underlying eBPF map. When externalCleanup is set to true, even if the map was recovered from an external
// source (pinned or rewritten from another manager), the map is cleaned up.
func (m *Map) Close(cleanup MapCleanupType) error {
	var shouldClose bool
	if m.AlwaysCleanup {
		shouldClose = true
	}
	if cleanup&CleanInternalPinned == CleanInternalPinned {
		if !m.externalMap && m.PinPath != "" {
			shouldClose = true
		}
	}
	if cleanup&CleanInternalNotPinned == CleanInternalNotPinned {
		if !m.externalMap && m.PinPath == "" {
			shouldClose = true
		}
	}
	if cleanup&CleanExternalPinned == CleanExternalPinned {
		if m.externalMap && m.PinPath != "" && !m.editedMap {
			shouldClose = true
		}
	}
	if cleanup&CleanExternalEdited == CleanExternalEdited {
		if m.externalMap && m.PinPath == "" && m.editedMap {
			shouldClose = true
		}
	}
	if cleanup&CleanExternalPinnedAndEdited == CleanExternalPinnedAndEdited {
		if m.externalMap && m.PinPath != "" && m.editedMap {
			shouldClose = true
		}
	}
	if shouldClose {
		var err error
		// Remove pin if needed
		if m.PinPath != "" {
			err = ConcatErrors(err, os.Remove(m.PinPath))
		}
		return ConcatErrors(err, m.array.Close())
	}
	return nil
}
