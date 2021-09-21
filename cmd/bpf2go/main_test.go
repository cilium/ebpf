package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Not compiling with -short")
	}

	dir := mustWriteTempFile(t, "test.c", minimalSocketFilter)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	modRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	if _, err := os.Stat(filepath.Join(modRoot, "go.mod")); os.IsNotExist(err) {
		t.Fatal("No go.mod file in", modRoot)
	}

	tmpDir, err := os.MkdirTemp("", "bpf2go-module-*")
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

	err = run(io.Discard, "foo", tmpDir, []string{
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

func TestCollectTargets(t *testing.T) {
	clangArches := make(map[string][]string)
	linuxArchesLE := make(map[string][]string)
	linuxArchesBE := make(map[string][]string)
	for arch, archTarget := range targetByGoArch {
		clangArches[archTarget.clang] = append(clangArches[archTarget.clang], arch)
		if archTarget.clang == "bpfel" {
			linuxArchesLE[archTarget.linux] = append(linuxArchesLE[archTarget.linux], arch)
			continue
		}
		linuxArchesBE[archTarget.linux] = append(linuxArchesBE[archTarget.linux], arch)
	}
	for i := range clangArches {
		sort.Strings(clangArches[i])
	}
	for i := range linuxArchesLE {
		sort.Strings(linuxArchesLE[i])
	}
	for i := range linuxArchesBE {
		sort.Strings(linuxArchesBE[i])
	}

	tests := []struct {
		targets []string
		want    map[target][]string
	}{
		{
			[]string{"bpf", "bpfel", "bpfeb"},
			map[target][]string{
				{"bpf", ""}:   nil,
				{"bpfel", ""}: clangArches["bpfel"],
				{"bpfeb", ""}: clangArches["bpfeb"],
			},
		},
		{
			[]string{"amd64", "386"},
			map[target][]string{
				{"bpfel", "x86"}: linuxArchesLE["x86"],
			},
		},
		{
			[]string{"amd64", "arm64be"},
			map[target][]string{
				{"bpfeb", "arm64"}: linuxArchesBE["arm64"],
				{"bpfel", "x86"}:   linuxArchesLE["x86"],
			},
		},
	}

	for _, test := range tests {
		name := strings.Join(test.targets, ",")
		t.Run(name, func(t *testing.T) {
			have, err := collectTargets(test.targets)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(test.want, have); diff != "" {
				t.Errorf("Result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCollectTargetsErrors(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"unknown", "frood"},
		{"no linux target", "mips64p32le"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := collectTargets([]string{test.target})
			if err == nil {
				t.Fatal("Function did not return an error")
			}
			t.Log("Error message:", err)
		})
	}
}

func TestConvertGOARCH(t *testing.T) {
	tmp := mustWriteTempFile(t, "test.c",
		`
#ifndef __TARGET_ARCH_x86
#error __TARGET_ARCH_x86 is not defined
#endif`,
	)

	b2g := bpf2go{
		pkg:        "test",
		stdout:     io.Discard,
		ident:      "test",
		cc:         "clang-9",
		sourceFile: tmp + "/test.c",
		outputDir:  tmp,
	}

	if err := b2g.convert(targetByGoArch["amd64"], nil); err != nil {
		t.Fatal("Can't target GOARCH:", err)
	}
}
