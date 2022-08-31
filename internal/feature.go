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

	mu         sync.RWMutex
	successful bool
	result     error
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
	return (&FeatureTest{
		Name:    name,
		Version: version,
		Fn:      fn,
	}).Result
}

// Result returns the outcome of a feature test, executing it if necessary.
//
// See [FeatureTestFn] for the meaning of the returned error.
func (ft *FeatureTest) Result() error {
	ft.mu.RLock()
	if ft.successful {
		defer ft.mu.RUnlock()
		return ft.result
	}
	ft.mu.RUnlock()
	ft.mu.Lock()
	defer ft.mu.Unlock()
	// check one more time on the off
	// chance that two go routines
	// were able to call into the write
	// lock
	if ft.successful {
		return ft.result
	}
	err := ft.Fn()
	switch {
	case errors.Is(err, ErrNotSupported):
		v, err := NewVersion(ft.Version)
		if err != nil {
			return err
		}

		ft.result = &UnsupportedFeatureError{
			MinimumVersion: v,
			Name:           ft.Name,
		}
		fallthrough

	case err == nil:
		ft.successful = true

	default:
		// We couldn't execute the feature test to a point
		// where it could make a determination.
		// Don't cache the result, just return it.
		return fmt.Errorf("detect support for %s: %w", ft.Name, err)
	}

	return ft.result
}

// FeatureMatrix groups multiple related feature tests into a map.
//
// Useful when there is a small number of discrete features.
//
// It must not be modified concurrently with calling [FeatureMatrix.Result].
type FeatureMatrix[K comparable] map[K]*FeatureTest

// Result returns the outcome of the feature test for the given key.
//
// It's safe to call this function concurrently.
func (fm FeatureMatrix[K]) Result(key K) error {
	ft, ok := fm[key]
	if !ok {
		return fmt.Errorf("no feature probe for %v", key)
	}

	return ft.Result()
}
