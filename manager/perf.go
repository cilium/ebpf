package manager

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/perf"
)

// PerfMapOptions - Perf map specific options
type PerfMapOptions struct {
	// PerfRingBufferSize - Size in bytes of the perf ring buffer. Defaults to the manager value if not set.
	PerfRingBufferSize int

	// Watermark - The reader will start processing samples once their sizes in the perf ring buffer
	// exceed this value. Must be smaller than PerfRingBufferSize. Defaults to the manager value if not set.
	Watermark int

	// PerfErrChan - Perf reader error channel
	PerfErrChan chan error

	// DataHandler - Callback function called when a new sample was retrieved from the perf
	// ring buffer.
	DataHandler func(CPU int, data []byte, perfMap *PerfMap, manager *Manager)

	// LostHandler - Callback function called when one or more events where dropped by the kernel
	// because the perf ring buffer was full.
	LostHandler func(CPU int, count uint64, perfMap *PerfMap, manager *Manager)
}

// PerfMap - Perf ring buffer reader wrapper
type PerfMap struct {
	manager     *Manager
	perfReader  *perf.Reader

	// Map - A PerfMap has the same features as a normal Map
	Map
	PerfMapOptions
}

// loadNewPerfMap - Creates a new perf map instance, loads it and setup the perf ring buffer reader
func loadNewPerfMap(spec ebpf.MapSpec, options MapOptions, perfOptions PerfMapOptions) (*PerfMap, error) {
	// Create underlying map
	innerMap, err := loadNewMap(spec, options)
	if err != nil {
		return nil, err
	}

	// Create the new map
	perfMap := PerfMap{
		Map: *innerMap,
		PerfMapOptions: perfOptions,
	}
	return &perfMap, nil
}

// Init - Initialize a map
func (m *PerfMap) Init(manager *Manager) error {
	m.manager = manager

	if m.DataHandler == nil {
		return fmt.Errorf("no DataHandler set for %s", m.Name)
	}

	// Set default values if not already set
	if m.PerfRingBufferSize == 0 {
		m.PerfRingBufferSize = manager.options.DefaultPerfRingBufferSize
	}
	if m.Watermark == 0 {
		m.Watermark = manager.options.DefaultWatermark
	}

	// Initialize the underlying map structure
	if err := m.Map.Init(manager); err != nil {
		return err
	}
	return nil
}

// Start - Starts fetching events on a perf ring buffer
func (m *PerfMap) Start() error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state == running {
		return nil
	}
	if m.state < initialized {
		return ErrMapNotInitialized
	}

	// Create and start the perf map
	var err error
	opt := perf.ReaderOptions{
		Watermark: m.Watermark,
	}
	if m.perfReader, err = perf.NewReaderWithOptions(m.array, m.PerfRingBufferSize, opt); err != nil {
		return err
	}
	// Start listening for data
	go func() {
		var record perf.Record
		var err error
		m.manager.wg.Add(1)
		for {
			record, err = m.perfReader.Read()
			if err != nil {
				if perf.IsClosed(err) {
					m.manager.wg.Done()
					return
				}
				if m.PerfErrChan != nil {
					m.PerfErrChan <- err
				}
				continue
			}
			if record.LostSamples > 0 {
				if m.LostHandler != nil {
					m.LostHandler(record.CPU, record.LostSamples, m, m.manager)
				}
				continue
			}
			m.DataHandler(record.CPU, record.RawSample, m, m.manager)
		}
	}()

	m.state = running
	return nil
}

// Stop - Stops the perf ring buffer
func (m *PerfMap) Stop(cleanup MapCleanupType) error {
	m.stateLock.Lock()
	defer m.stateLock.Unlock()
	if m.state < running {
		return nil
	}

	// close perf reader
	err := m.perfReader.Close()

	// close underlying map
	if errTmp := m.Map.close(cleanup); errTmp != nil {
		if err == nil {
			err = errTmp
		} else {
			err = errors.Wrap(errTmp, err.Error())
		}
	}
	return err
}

// Pause - Pauses a perf ring buffer reader
func (m *PerfMap) Pause() error {
	m.stateLock.RLock()
	defer m.stateLock.RUnlock()
	if m.state < running {
		return ErrMapNotRunning
	}
	if err := m.perfReader.Pause(); err != nil {
		return err
	}
	m.state = paused
	return nil
}

// Resume - Resumes a perf ring buffer reader
func (m *PerfMap) Resume() error {
	if m.state < paused {
		return ErrMapNotRunning
	}
	if err := m.perfReader.Resume(); err != nil {
		return err
	}
	m.state = running
	return nil
}
