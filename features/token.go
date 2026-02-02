package features

import "github.com/cilium/ebpf/internal/token"

// SetGlobalToken sets the global BPF token file descriptor for feature probes.
//
// This should be called early during initialization before any feature probes
// run. The token is used by feature detection to accurately probe kernel
// capabilities when running in user namespaces with delegated BPF permissions.
//
// When a token is set, feature probes will pass it to the kernel during
// capability detection. This allows accurate feature detection even when
// running without CAP_BPF in the initial user namespace.
//
// The caller is responsible for keeping the file descriptor open for the
// lifetime of the program. Passing -1 clears the global token.
func SetGlobalToken(fd int) {
	token.SetGlobalToken(fd)
}

// GetGlobalToken returns the global BPF token file descriptor, or -1 if not set.
func GetGlobalToken() int {
	return token.GetGlobalToken()
}
