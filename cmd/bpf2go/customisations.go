package main

import (
	"flag"
	"io"
	"os/exec"

	"github.com/cilium/ebpf"
)

// Run implements bpf2go tool; leverage bpf2go and build custom tools on
// top by providing Customisations
func Run(stdout io.Writer, pkg, outputDir string, args []string, c Customisations) (err error) {
	return run(stdout, pkg, outputDir, args, c)
}

// Customisations enables building custom tools on top of bpf2go
type Customisations interface {
	// ModifyFlags adds custom tool's own flags
	ModifyFlags(*flag.FlagSet)

	// NewTarget provides decdicated TargetCustomisations per target; a
	// custom tool implements further customisations via
	// TargetCustomisations (can contain target-specific state)
	NewTarget(target) TargetCustomisations
}

// TargetCustomisations enables building custom tools on top of bpf2go
type TargetCustomisations interface {
	// Compile compiles C source code; instead of running the provided
	// command as is, a custom tool could do something more exciting,
	// such as transparently running compiler in a Docker container or
	// implement a cache, or even run a custom preprocessor to have
	// e.g. golang package-aware includes
	Compile(*exec.Cmd) error

	// Strip strips the object file; instead of running the provided
	// command as is, a custom tool could do something more exciting
	// such as transparently running strip in a Docker container or
	// implement a cache
	Strip(*exec.Cmd) error

	// AugmentSpec optionally adds to the spec; e.g. a custom tool could
	// add types from DWARF debug info so that the tool could generate
	// golang type even when C type is not included in BTF
	AugmentSpec(*ebpf.CollectionSpec) error
}

// CustomisationsBase is a baseline implementation of Cusomisations,
// TargetCustomisations
type CustomisationsBase struct{}

func (cb *CustomisationsBase) ModifyFlags(fs *flag.FlagSet) {}

func (cb *CustomisationsBase) NewTarget(target) TargetCustomisations { return cb }

func (cb *CustomisationsBase) Compile(cmd *exec.Cmd) error {
	return cmd.Run()
}

func (cb *CustomisationsBase) Strip(cmd *exec.Cmd) error {
	return cmd.Run()
}

func (cb *CustomisationsBase) AugmentSpec(*ebpf.CollectionSpec) error {
	return nil
}
