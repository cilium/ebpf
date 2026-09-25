// Package features allows probing for BPF features available to the calling process.
//
// In general, the error return values from feature probes in this package
// all have the following semantics unless otherwise specified:
//
//	err == nil: The feature is available.
//	errors.Is(err, ebpf.ErrNotSupported): The feature is not available.
//	err != nil: Any errors encountered during probe execution, wrapped.
//
// A non `ebpf.ErrNotSupported` error indicates an unexpected failure and is inconclusive.
//
// Kernel BTF is used to determine the availability of certain BPF features. A probe
// may return a positive result, yet the feature might still be unavailable due to kernel
// configuration or security constraints.
package features
