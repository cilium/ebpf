package token

import "sync/atomic"

// globalTokenFD stores the BPF token file descriptor for use in feature probes
// and other operations that need a default token. A value of -1 means no token
// is set.
var globalTokenFD atomic.Int32

func init() {
	globalTokenFD.Store(-1)
}

// SetGlobalToken sets the global BPF token file descriptor.
//
// This should be called early during initialization before any feature probes
// run. The token is used by feature detection to accurately probe kernel
// capabilities when running in user namespaces with delegated BPF permissions.
//
// The caller is responsible for keeping the file descriptor open for the
// lifetime of the program. Passing -1 clears the global token.
func SetGlobalToken(fd int) {
	globalTokenFD.Store(int32(fd))
}

// GetGlobalToken returns the global BPF token file descriptor, or -1 if not set.
func GetGlobalToken() int {
	return int(globalTokenFD.Load())
}
