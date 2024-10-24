//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/cmd/bpf2go/gen"
	"github.com/cilium/ebpf/cmd/bpf2go/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

const minimalSocketFilter = `__attribute__((section("socket"), used)) int main() { return 0; }`

func TestRun(t *testing.T) {
	clangBin := testutils.ClangBin(t)
	dir := t.TempDir()
	mustWriteFile(t, dir, "test.c", minimalSocketFilter)

	modRoot, err := filepath.Abs("../..")
	qt.Assert(t, qt.IsNil(err))

	if _, err := os.Stat(filepath.Join(modRoot, "go.mod")); os.IsNotExist(err) {
		t.Fatal("No go.mod file in", modRoot)
	}

	modDir := t.TempDir()
	execInModule := func(name string, args ...string) {
		t.Helper()

		cmd := exec.Command(name, args...)
		cmd.Dir = modDir
		if out, err := cmd.CombinedOutput(); err != nil {
			if out := string(out); out != "" {
				t.Log(out)
			}
			t.Fatalf("Can't execute %s: %v", name, args)
		}
	}

	module := internal.CurrentModule

	execInModule("go", "mod", "init", "bpf2go-test")

	execInModule("go", "mod", "edit",
		// Require the module. The version doesn't matter due to the replace
		// below.
		fmt.Sprintf("-require=%s@v0.0.0", module),
		// Replace the module with the current version.
		fmt.Sprintf("-replace=%s=%s", module, modRoot),
	)

	goarches := []string{
		"amd64", // little-endian
		"arm64",
		"s390x", // big-endian
	}

	err = run(io.Discard, []string{
		"-go-package", "main",
		"-output-dir", modDir,
		"-cc", clangBin,
		"-target", strings.Join(goarches, ","),
		"bar",
		filepath.Join(dir, "test.c"),
	})

	if err != nil {
		t.Fatal("Can't run:", err)
	}

	mustWriteFile(t, modDir, "main.go",
		`
package main

func main() {
	var obj barObjects
	println(obj.Main)
}`)

	for _, arch := range goarches {
		t.Run(arch, func(t *testing.T) {
			goBuild := exec.Command("go", "build", "-mod=mod", "-o", "/dev/null")
			goBuild.Dir = modDir
			goBuild.Env = append(os.Environ(),
				"GOOS=linux",
				"GOARCH="+arch,
				"GOPROXY=off",
				"GOSUMDB=off",
			)
			out, err := goBuild.CombinedOutput()
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
	err := run(&stdout, []string{"-help"})
	if err != nil {
		t.Fatal("Can't execute -help")
	}

	if stdout.Len() == 0 {
		t.Error("-help doesn't write to stdout")
	}
}

func TestErrorMentionsEnvVar(t *testing.T) {
	err := run(io.Discard, nil)
	qt.Assert(t, qt.StringContains(err.Error(), gopackageEnv), qt.Commentf("Error should include name of environment variable"))
}

func TestDisableStripping(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, dir, "test.c", minimalSocketFilter)

	err := run(io.Discard, []string{
		"-go-package", "foo",
		"-output-dir", dir,
		"-cc", testutils.ClangBin(t),
		"-strip", "binary-that-certainly-doesnt-exist",
		"-no-strip",
		"bar",
		filepath.Join(dir, "test.c"),
	})

	if err != nil {
		t.Fatal("Can't run with stripping disabled:", err)
	}
}

func TestConvertGOARCH(t *testing.T) {
	tmp := t.TempDir()
	mustWriteFile(t, tmp, "test.c",
		`
#ifndef __TARGET_ARCH_x86
#error __TARGET_ARCH_x86 is not defined
#endif`,
	)

	b2g := bpf2go{
		pkg:              "test",
		stdout:           io.Discard,
		identStem:        "test",
		cc:               testutils.ClangBin(t),
		disableStripping: true,
		sourceFile:       tmp + "/test.c",
		outputDir:        tmp,
	}

	if err := b2g.convert(gen.TargetsByGoArch()["amd64"], nil); err != nil {
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
	qt.Assert(t, qt.ContentEquals(ct, valid))

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
	qt.Assert(t, qt.IsNil(ct.Set("foo")))
	qt.Assert(t, qt.IsNotNil(ct.Set("foo")))
}

func TestParseArgs(t *testing.T) {
	const (
		pkg       = "eee"
		outputDir = "."
		csource   = "testdata/minimal.c"
		stem      = "a"
	)
	t.Run("makebase", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		basePath, _ := filepath.Abs("barfoo")
		args := []string{"-makebase", basePath, stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.makeBase, basePath))
	})

	t.Run("makebase from env", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		basePath, _ := filepath.Abs("barfoo")
		args := []string{stem, csource}
		t.Setenv("BPF2GO_MAKEBASE", basePath)
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.makeBase, basePath))
	})

	t.Run("makebase flag overrides env", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		basePathFlag, _ := filepath.Abs("barfoo")
		basePathEnv, _ := filepath.Abs("foobar")
		args := []string{"-makebase", basePathFlag, stem, csource}
		t.Setenv("BPF2GO_MAKEBASE", basePathEnv)
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.makeBase, basePathFlag))
	})

	t.Run("cc defaults to clang", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.cc, "clang"))
	})

	t.Run("cc", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-cc", "barfoo", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.cc, "barfoo"))
	})

	t.Run("cc from env", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{stem, csource}
		t.Setenv("BPF2GO_CC", "barfoo")
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.cc, "barfoo"))
	})

	t.Run("cc flag overrides env", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-cc", "barfoo", stem, csource}
		t.Setenv("BPF2GO_CC", "foobar")
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.cc, "barfoo"))
	})

	t.Run("strip defaults to llvm-strip", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.strip, "llvm-strip"))
	})

	t.Run("strip", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-strip", "barfoo", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.strip, "barfoo"))
	})

	t.Run("strip from env", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{stem, csource}
		t.Setenv("BPF2GO_STRIP", "barfoo")
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.strip, "barfoo"))
	})

	t.Run("strip flag overrides env", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-strip", "barfoo", stem, csource}
		t.Setenv("BPF2GO_STRIP", "foobar")
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.strip, "barfoo"))
	})

	t.Run("no strip defaults to false", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsFalse(b2g.disableStripping))
	})

	t.Run("no strip", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-no-strip", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsTrue(b2g.disableStripping))
	})

	t.Run("cflags flag", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-cflags", "x y z", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.DeepEquals(b2g.cFlags, []string{"x", "y", "z"}))
	})

	t.Run("cflags multi flag", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-cflags", "x y z", "-cflags", "u v", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.DeepEquals(b2g.cFlags, []string{"u", "v"}))
	})

	t.Run("cflags flag and args", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-cflags", "x y z", "stem", csource, "--", "u", "v"}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.DeepEquals(b2g.cFlags, []string{"x", "y", "z", "u", "v"}))
	})

	t.Run("cflags from env", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{stem, csource}
		t.Setenv("BPF2GO_CFLAGS", "x y z")
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.DeepEquals(b2g.cFlags, []string{"x", "y", "z"}))
	})

	t.Run("cflags flag overrides env", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-cflags", "u v", stem, csource}
		t.Setenv("BPF2GO_CFLAGS", "x y z")
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.DeepEquals(b2g.cFlags, []string{"u", "v"}))
	})

	t.Run("go package overrides env", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-go-package", "aaa", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.pkg, "aaa"))
	})

	t.Run("output dir", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		args := []string{"-output-dir", outputDir, stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.outputDir, outputDir))
	})

	t.Run("output suffix default", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		b2g, err := newB2G(&bytes.Buffer{}, []string{stem, csource})
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.outputSuffix, ""))
	})

	t.Run("output suffix GOFILE=_test", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		t.Setenv("GOFILE", "foo_test.go")
		b2g, err := newB2G(&bytes.Buffer{}, []string{stem, csource})
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.outputSuffix, "_test"))
	})

	t.Run("output suffix custom", func(t *testing.T) {
		t.Setenv(gopackageEnv, pkg)
		t.Setenv("GOFILE", "foo_test.go")
		args := []string{"-output-suffix", "_custom", stem, csource}
		b2g, err := newB2G(&bytes.Buffer{}, args)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(b2g.outputSuffix, "_custom"))
	})
}

func mustWriteFile(tb testing.TB, dir, name, contents string) {
	tb.Helper()
	tmpFile := filepath.Join(dir, name)
	if err := os.WriteFile(tmpFile, []byte(contents), 0660); err != nil {
		tb.Fatal(err)
	}
}
