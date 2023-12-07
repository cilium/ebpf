package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type compileArgs struct {
	// Which compiler to use
	cc     string
	cFlags []string
	// Absolute working directory
	dir string
	// Absolute input file name
	source string
	// Absolute output file name
	dest string
	// Target to compile for, defaults to "bpf".
	target string
	// Depfile will be written here if depName is not empty
	dep io.Writer
}

func compile(args compileArgs) error {
	// Default cflags that can be overridden by args.cFlags
	overrideFlags := []string{
		// Code needs to be optimized, otherwise the verifier will often fail
		// to understand it.
		"-O2",
		// Clang defaults to mcpu=probe which checks the kernel that we are
		// compiling on. This isn't appropriate for ahead of time
		// compiled code so force the most compatible version.
		"-mcpu=v1",
	}

	cmd := exec.Command(args.cc, append(overrideFlags, args.cFlags...)...)
	cmd.Stderr = os.Stderr

	inputDir := filepath.Dir(args.source)
	relInputDir, err := filepath.Rel(args.dir, inputDir)
	if err != nil {
		return err
	}

	target := args.target
	if target == "" {
		target = "bpf"
	}

	// C flags that can't be overridden.
	cmd.Args = append(cmd.Args,
		"-target", target,
		"-c", args.source,
		"-o", args.dest,
		// Don't include clang version
		"-fno-ident",
		// Don't output inputDir into debug info
		"-fdebug-prefix-map="+inputDir+"="+relInputDir,
		"-fdebug-compilation-dir", ".",
		// We always want BTF to be generated, so enforce debug symbols
		"-g",
		fmt.Sprintf("-D__BPF_TARGET_MISSING=%q", "GCC error \"The eBPF is using target specific macros, please provide -target that is not bpf, bpfel or bpfeb\""),
	)
	cmd.Dir = args.dir

	var depFile *os.File
	if args.dep != nil {
		depFile, err = os.CreateTemp("", "bpf2go")
		if err != nil {
			return err
		}
		defer depFile.Close()
		defer os.Remove(depFile.Name())

		cmd.Args = append(cmd.Args,
			// Output dependency information.
			"-MD",
			// Create phony targets so that deleting a dependency doesn't
			// break the build.
			"-MP",
			// Write it to temporary file
			"-MF"+depFile.Name(),
		)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("can't execute %s: %s", args.cc, err)
	}

	if depFile != nil {
		if _, err := io.Copy(args.dep, depFile); err != nil {
			return fmt.Errorf("error writing depfile: %w", err)
		}
	}

	return nil
}

func adjustDependencies(baseDir string, deps []dependency) ([]byte, error) {
	var buf bytes.Buffer
	for _, dep := range deps {
		relativeFile, err := filepath.Rel(baseDir, dep.file)
		if err != nil {
			return nil, err
		}

		if len(dep.prerequisites) == 0 {
			_, err := fmt.Fprintf(&buf, "%s:\n\n", relativeFile)
			if err != nil {
				return nil, err
			}
			continue
		}

		var prereqs []string
		for _, prereq := range dep.prerequisites {
			relativePrereq, err := filepath.Rel(baseDir, prereq)
			if err != nil {
				return nil, err
			}

			prereqs = append(prereqs, relativePrereq)
		}

		_, err = fmt.Fprintf(&buf, "%s: \\\n %s\n\n", relativeFile, strings.Join(prereqs, " \\\n "))
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

type dependency struct {
	file          string
	prerequisites []string
}

func parseDependencies(baseDir string, in io.Reader) ([]dependency, error) {
	abs := func(path string) string {
		if filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(baseDir, path)
	}

	scanner := bufio.NewScanner(in)
	var line strings.Builder
	var deps []dependency
	for scanner.Scan() {
		buf := scanner.Bytes()
		if line.Len()+len(buf) > 1024*1024 {
			return nil, errors.New("line too long")
		}

		if bytes.HasSuffix(buf, []byte{'\\'}) {
			line.Write(buf[:len(buf)-1])
			continue
		}

		line.Write(buf)
		if line.Len() == 0 {
			// Skip empty lines
			continue
		}

		parts := strings.SplitN(line.String(), ":", 2)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid line without ':'")
		}

		// NB: This doesn't handle filenames with spaces in them.
		// It seems like make doesn't do that either, so oh well.
		var prereqs []string
		for _, prereq := range strings.Fields(parts[1]) {
			prereqs = append(prereqs, abs(prereq))
		}

		deps = append(deps, dependency{
			abs(string(parts[0])),
			prereqs,
		})
		line.Reset()
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// There is always at least a dependency for the main file.
	if len(deps) == 0 {
		return nil, fmt.Errorf("empty dependency file")
	}
	return deps, nil
}

// strip DWARF debug info from file by executing exe.
func strip(exe, file string) error {
	cmd := exec.Command(exe, "-g", file)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %s", exe, err)
	}
	return nil
}
