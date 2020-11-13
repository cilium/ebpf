package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	dir := mustWriteTempFile(t, "test.c", minimalSocketFilter)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	modRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	if _, err := os.Stat(filepath.Join(modRoot, "go.mod")); os.IsNotExist(err) {
		t.Fatal("No go.mod file in", modRoot)
	}

	tmpDir, err := ioutil.TempDir("", "bpf2go-module-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	execInModule := func(name string, args ...string) {
		t.Helper()

		cmd := exec.Command(name, args...)
		cmd.Dir = tmpDir
		if out, err := cmd.CombinedOutput(); err != nil {
			if out := string(out); out != "" {
				t.Log(out)
			}
			t.Fatalf("Can't execute %s: %v", name, args)
		}
	}

	execInModule("go", "mod", "init", "bpf2go-test")

	execInModule("go", "mod", "edit",
		// Require the module. The version doesn't matter due to the replace
		// below.
		fmt.Sprintf("-require=%s@v0.0.0", ebpfModule),
		// Replace the module with the current version.
		fmt.Sprintf("-replace=%s=%s", ebpfModule, modRoot),
	)

	err = run(ioutil.Discard, "foo", tmpDir, []string{
		"-cc", "clang-9",
		"bar",
		filepath.Join(dir, "test.c"),
	})

	if err != nil {
		t.Fatal("Can't run:", err)
	}

	for _, arch := range []string{
		"amd64", // little-endian
		"s390x", // big-endian
	} {
		t.Run(arch, func(t *testing.T) {
			goBin := exec.Command("go", "build", "-mod=mod")
			goBin.Dir = tmpDir
			goBin.Env = append(os.Environ(),
				"GOOS=linux",
				"GOARCH="+arch,
			)
			out, err := goBin.CombinedOutput()
			if err != nil {
				if out := string(out); out != "" {
					t.Log(out)
				}
				t.Error("Can't compile package:", err)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	var stdout bytes.Buffer
	err := run(&stdout, "", "", []string{"-help"})
	if err != nil {
		t.Fatal("Can't execute -help")
	}

	if stdout.Len() == 0 {
		t.Error("-help doesn't write to stdout")
	}
}
