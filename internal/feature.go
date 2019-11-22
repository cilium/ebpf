package internal

import (
	"sync"
)

// FeatureTest wraps a function so that it is run at most once.
func FeatureTest(fn func() bool) func() bool {
	var (
		once   sync.Once
		result bool
	)

	return func() bool {
		once.Do(func() {
			result = fn()
		})
		return result
	}
}
