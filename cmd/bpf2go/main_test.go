package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	dir, cleanup := mustWriteTempFile(t, "test.c", minimalSocketFilter)
	defer cleanup()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// The temporary package has to be in the same module, otherwise
	// we can't test against unreleased versions of the package.
	tmpDir, err := ioutil.TempDir(cwd, "bpf2go-module-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

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
		goBin := exec.Command("go", "build", tmpDir)
		goBin.Env = append(os.Environ(),
			"GOOS=linux",
			"GOARCH="+arch,
		)
		out, err := goBin.CombinedOutput()
		if err != nil {
			if out := string(out); out != "" {
				t.Log(out)
			}
			t.Errorf("Can't compile resulting package for arch %s: %s", arch, err)
		}
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
