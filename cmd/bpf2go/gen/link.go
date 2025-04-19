//go:build !windows

package gen

import (
	"fmt"
	"os"
	"os/exec"
)

// LinkArgs specifies the arguments for linking multiple BPF object files together.
type LinkArgs struct {
	// Destination object file name
	Dest string
	// Source object files to link together
	Sources []string
}

// Link combines multiple BPF object files into a single object file.
func Link(args LinkArgs) error {
	if len(args.Sources) == 0 {
		return fmt.Errorf("no source files to link")
	}

	cmd := exec.Command("bpftool", "gen", "object", args.Dest)
	cmd.Args = append(cmd.Args, args.Sources...)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bpftool gen object returned error: %w", err)
	}

	return nil
}
