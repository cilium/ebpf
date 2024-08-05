// Program genstrings allows invoking stringer for types which have different values on Linux and Windows.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func run() error {
	flag := flag.NewFlagSet("genstrings", flag.ExitOnError)
	flag.Usage = func() {
		fmt.Fprintln(flag.Output(), "Usage: genstrings <stem> [stringer flags]")
	}
	flag.Parse(os.Args[1:])
	if flag.NArg() < 1 {
		flag.Usage()
		return fmt.Errorf("expected at least two arguments")
	}

	stringer, err := buildStringer()
	if err != nil {
		return err
	}

	stem := flag.Arg(0)
	for _, goos := range []string{
		"linux",
		"windows",
	} {
		output := fmt.Sprintf("%s_%s.go", stem, goos)
		cmd := exec.Command(stringer, flag.Args()[1:]...)
		cmd.Args = append(cmd.Args,
			"-output", output,
			"-tags", goos,
		)
		cmd.Env = cmd.Environ()
		cmd.Env = append(cmd.Env, "GOOS="+goos)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute %v: %w", cmd.Args, err)
		}
	}

	return nil
}

func buildStringer() (string, error) {
	temp, err := os.MkdirTemp("", "ebpf-go")
	if err != nil {
		return "", err
	}

	build := exec.Command("go", "install", "golang.org/x/tools/cmd/stringer@latest")
	build.Env = build.Environ()
	build.Env = append(build.Env, "GOBIN="+temp)
	out, err := build.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("compile stringer: %w: %s", err, string(out))
	}

	return filepath.Join(temp, "stringer"), nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
