package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
)

func TestRun(t *testing.T) {
	tmpFile := mustWriteTempFile(t, "test.c", minimalSocketFilter)

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
		"bar",
		tmpFile,
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
			t.Log(string(out))
			t.Error("Can't compile resulting package for arch", arch)
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
