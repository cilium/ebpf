package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp"
)

func TestRun(t *testing.T) {
	clangBin := clangBin(t)
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

	module := currentModule()

	execInModule("go", "mod", "init", "bpf2go-test")

	execInModule("go", "mod", "edit",
		// Require the module. The version doesn't matter due to the replace
		// below.
		fmt.Sprintf("-require=%s@v0.0.0", module),
		// Replace the module with the current version.
		fmt.Sprintf("-replace=%s=%s", module, modRoot),
	)

	err = run(io.Discard, "foo", tmpDir, []string{
		"-cc", clangBin,
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

func TestDisableStripping(t *testing.T) {
	dir := mustWriteTempFile(t, "test.c", minimalSocketFilter)

	err := run(io.Discard, "foo", dir, []string{
		"-cc", clangBin(t),
		"-strip", "binary-that-certainly-doesnt-exist",
		"-no-strip",
		"bar",
		filepath.Join(dir, "test.c"),
	})

	if err != nil {
		t.Fatal("Can't run with stripping disabled:", err)
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

	nativeTarget := make(map[target][]string)
	for arch, archTarget := range targetByGoArch {
		if arch == runtime.GOARCH {
			if archTarget.clang == "bpfel" {
				nativeTarget[archTarget] = linuxArchesLE[archTarget.linux]
			} else {
				nativeTarget[archTarget] = linuxArchesBE[archTarget.linux]
			}
			break
		}
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
		{
			[]string{"native"},
			nativeTarget,
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
		pkg:              "test",
		stdout:           io.Discard,
		identStem:        "test",
		cc:               clangBin(t),
		disableStripping: true,
		sourceFile:       tmp + "/test.c",
		outputDir:        tmp,
	}

	if err := b2g.convert(targetByGoArch["amd64"], nil); err != nil {
		t.Fatal("Can't target GOARCH:", err)
	}
}

func TestCTypes(t *testing.T) {
	var ct cTypes
	valid := []string{
		"abcdefghijklmnopqrstuvqxyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_",
		"y",
	}
	for _, value := range valid {
		if err := ct.Set(value); err != nil {
			t.Fatalf("Set returned an error for %q: %s", value, err)
		}
	}
	qt.Assert(t, ct, qt.ContentEquals, cTypes(valid))

	for _, value := range []string{
		"",
		" ",
		" frood",
		"foo\nbar",
		".",
		",",
		"+",
		"-",
	} {
		ct = nil
		if err := ct.Set(value); err == nil {
			t.Fatalf("Set did not return an error for %q", value)
		}
	}

	ct = nil
	qt.Assert(t, ct.Set("foo"), qt.IsNil)
	qt.Assert(t, ct.Set("foo"), qt.IsNotNil)
}

func TestParseArgs(t *testing.T) {
	const (
		pkg       = "eee"
		outputDir = "."
		csource   = "testdata/minimal.c"
		stem      = "a"
	)

	t.Run("makebase", func(t *testing.T) {
		basePath, _ := filepath.Abs("barfoo")
		args := []string{"-makebase", basePath, stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.makeBase, qt.Equals, basePath)
	})

	t.Run("makebase from env", func(t *testing.T) {
		basePath, _ := filepath.Abs("barfoo")
		args := []string{stem, csource}
		t.Setenv("BPF2GO_MAKEBASE", basePath)
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.makeBase, qt.Equals, basePath)
	})

	t.Run("makebase flag overrides env", func(t *testing.T) {
		basePathFlag, _ := filepath.Abs("barfoo")
		basePathEnv, _ := filepath.Abs("foobar")
		args := []string{"-makebase", basePathFlag, stem, csource}
		t.Setenv("BPF2GO_MAKEBASE", basePathEnv)
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.makeBase, qt.Equals, basePathFlag)
	})

	t.Run("cc defaults to clang", func(t *testing.T) {
		args := []string{stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.cc, qt.Equals, "clang")
	})

	t.Run("cc", func(t *testing.T) {
		args := []string{"-cc", "barfoo", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.cc, qt.Equals, "barfoo")
	})

	t.Run("cc from env", func(t *testing.T) {
		args := []string{stem, csource}
		t.Setenv("BPF2GO_CC", "barfoo")
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.cc, qt.Equals, "barfoo")
	})

	t.Run("cc flag overrides env", func(t *testing.T) {
		args := []string{"-cc", "barfoo", stem, csource}
		t.Setenv("BPF2GO_CC", "foobar")
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.cc, qt.Equals, "barfoo")
	})

	t.Run("strip defaults to llvm-strip", func(t *testing.T) {
		args := []string{stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.strip, qt.Equals, "llvm-strip")
	})

	t.Run("strip", func(t *testing.T) {
		args := []string{"-strip", "barfoo", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.strip, qt.Equals, "barfoo")
	})

	t.Run("strip from env", func(t *testing.T) {
		args := []string{stem, csource}
		t.Setenv("BPF2GO_STRIP", "barfoo")
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.strip, qt.Equals, "barfoo")
	})

	t.Run("strip flag overrides env", func(t *testing.T) {
		args := []string{"-strip", "barfoo", stem, csource}
		t.Setenv("BPF2GO_STRIP", "foobar")
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.strip, qt.Equals, "barfoo")
	})

	t.Run("no strip defaults to false", func(t *testing.T) {
		args := []string{stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.disableStripping, qt.IsFalse)
	})

	t.Run("no strip", func(t *testing.T) {
		args := []string{"-no-strip", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.disableStripping, qt.IsTrue)
	})

	t.Run("cflags flag", func(t *testing.T) {
		args := []string{"-cflags", "x y z", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.cFlags, qt.DeepEquals, []string{"x", "y", "z"})
	})

	t.Run("cflags multi flag", func(t *testing.T) {
		args := []string{"-cflags", "x y z", "-cflags", "u v", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.cFlags, qt.DeepEquals, []string{"u", "v"})
	})

	t.Run("cflags flag and args", func(t *testing.T) {
		args := []string{"-cflags", "x y z", "stem", csource, "--", "u", "v"}
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.cFlags, qt.DeepEquals, []string{"x", "y", "z", "u", "v"})
	})

	t.Run("cflags from env", func(t *testing.T) {
		args := []string{stem, csource}
		t.Setenv("BPF2GO_CFLAGS", "x y z")
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.cFlags, qt.DeepEquals, []string{"x", "y", "z"})
	})

	t.Run("cflags flag overrides env", func(t *testing.T) {
		args := []string{"-cflags", "u v", stem, csource}
		t.Setenv("BPF2GO_CFLAGS", "x y z")
		b2g, err := newB2G(&bytes.Buffer{}, pkg, outputDir, args)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, b2g.cFlags, qt.DeepEquals, []string{"u", "v"})
	})
}

func clangBin(t *testing.T) string {
	t.Helper()

	if testing.Short() {
		t.Skip("Not compiling with -short")
	}

	// Use a recent clang version for local development, but allow CI to run
	// against oldest supported clang.
	clang := "clang-14"
	if minVersion := os.Getenv("CI_MIN_CLANG_VERSION"); minVersion != "" {
		clang = fmt.Sprintf("clang-%s", minVersion)
	}

	t.Log("Testing against", clang)
	return clang
}
