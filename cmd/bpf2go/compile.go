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
	// Absolute input file name
	file string
	// Compiled ELF will be written here
	out io.Writer
	// Depfile will be written here if depName is not empty
	dep io.Writer
}

func compile(args compileArgs) error {
	cmd := exec.Command(args.cc, args.cFlags...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = args.out

	inputDir := filepath.Dir(args.file)
	cmd.Args = append(cmd.Args,
		"-c", args.file,
		"-o", "-",
		// Don't output inputDir into debug info
		"-fdebug-prefix-map="+inputDir+"=.",
		// We always want BTF to be generated, so enforce debug symbols
		"-g",
	)

	var (
		depRd, depWr *os.File
		err          error
	)
	if args.dep != nil {
		depRd, depWr, err = os.Pipe()
		if err != nil {
			return err
		}
		defer depRd.Close()
		defer depWr.Close()

		// This becomes /dev/fd/3
		cmd.ExtraFiles = append(cmd.ExtraFiles, depWr)
		cmd.Args = append(cmd.Args,
			// Output dependency information.
			"-MD",
			// Create phony targets so that deleting a dependency doesn't
			// break the build.
			"-MP",
			// Write it to our pipe
			"-MF/dev/fd/3",
		)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("can't execute %s: %s", args.cc, err)
	}

	if depRd != nil {
		// Close our copy of the write end so that Copy will terminate
		// when cc exits.
		depWr.Close()
		io.Copy(args.dep, depRd)
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %s", args.cc, err)
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
