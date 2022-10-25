package internal

import (
	"errors"
	"fmt"
	"sync"
)

// ErrNotSupported indicates that a feature is not supported by the current kernel.
var ErrNotSupported = errors.New("not supported")

// UnsupportedFeatureError is returned by FeatureTest() functions.
type UnsupportedFeatureError struct {
	// The minimum Linux mainline version required for this feature.
	// Used for the error string, and for sanity checking during testing.
	MinimumVersion Version

	// The name of the feature that isn't supported.
	Name string
}

func (ufe *UnsupportedFeatureError) Error() string {
	if ufe.MinimumVersion.Unspecified() {
		return fmt.Sprintf("%s not supported", ufe.Name)
	}
	return fmt.Sprintf("%s not supported (requires >= %s)", ufe.Name, ufe.MinimumVersion)
}

// Is indicates that UnsupportedFeatureError is ErrNotSupported.
func (ufe *UnsupportedFeatureError) Is(target error) bool {
	return target == ErrNotSupported
}

// FeatureTest caches the result of a [FeatureTestFn].
//
// Fields should not be modified after creation.
type FeatureTest struct {
	// The name of the feature being detected.
	Name string
	// Version in in the form Major.Minor[.Patch].
	Version string
	// The feature test itself.
	Fn FeatureTestFn

	mu     sync.RWMutex
	done   bool
	result error
}

// FeatureTestFn is used to determine whether the kernel supports
// a certain feature.
//
// The return values have the following semantics:
//
//	err == ErrNotSupported: the feature is not available
//	err == nil: the feature is available
//	err != nil: the test couldn't be executed
type FeatureTestFn func() error

// NewFeatureTest is a convenient way to create a single [FeatureTest].
func NewFeatureTest(name, version string, fn FeatureTestFn) func() error {
	ft := &FeatureTest{
		Name:    name,
		Version: version,
		Fn:      fn,
	}

	return ft.execute
}

func (ft *FeatureTest) retrieve() (error, bool) {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	return ft.result, ft.done
}

// execute the feature test.
//
// The result is cached if the test is conclusive.
//
// See [FeatureTestFn] for the meaning of the returned error.
func (ft *FeatureTest) execute() error {
	if result, done := ft.retrieve(); done {
		return result
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	// The test may have been executed by another caller while we were
	// waiting to acquire ft.mu.
	if ft.done {
		return ft.result
	}

	err := ft.Fn()
	if err == nil {
		ft.done = true
		return nil
	}

	if errors.Is(err, ErrNotSupported) {
		v, err := NewVersion(ft.Version)
		if err != nil {
			return fmt.Errorf("feature %s: %w", ft.Name, err)
		}

		ft.done = true
		ft.result = &UnsupportedFeatureError{
			MinimumVersion: v,
			Name:           ft.Name,
		}

		return ft.result
	}

	// We couldn't execute the feature test to a point
	// where it could make a determination.
	// Don't cache the result, just return it.
	return fmt.Errorf("detect support for %s: %w", ft.Name, err)
}

// FeatureMatrix groups multiple related feature tests into a map.
//
// You musn't modify a FeatureMatrix concurrently with calling [FeatureMatrix.Result].
type FeatureMatrix[K comparable] map[K]*FeatureTest

// Result returns the outcome of the feature test for the given key.
//
// It's safe to call this function concurrently.
func (fm FeatureMatrix[K]) Result(key K) error {
	ft, ok := fm[key]
	if !ok {
		return fmt.Errorf("no feature probe for %v", key)
	}

	return ft.execute()
}
