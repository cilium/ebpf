package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/google/go-cmp/cmp"
)

func TestRun(t *testing.T) {
	clangBin := clangBin(t)
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

	module := currentModule()

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
	clangArches := make(map[string][]goarch)
	linuxArchesLE := make(map[string][]goarch)
	linuxArchesBE := make(map[string][]goarch)
	for arch, archTarget := range targetByGoArch {
		clangArches[archTarget.clang] = append(clangArches[archTarget.clang], arch)
		if archTarget.clang == "bpfel" {
			linuxArchesLE[archTarget.linux] = append(linuxArchesLE[archTarget.linux], arch)
			continue
		}
		linuxArchesBE[archTarget.linux] = append(linuxArchesBE[archTarget.linux], arch)
	}
	for i := range clangArches {
		slices.Sort(clangArches[i])
	}
	for i := range linuxArchesLE {
		slices.Sort(linuxArchesLE[i])
	}
	for i := range linuxArchesBE {
		slices.Sort(linuxArchesBE[i])
	}

	nativeTarget := make(map[target][]goarch)
	for arch, archTarget := range targetByGoArch {
		if arch == goarch(runtime.GOARCH) {
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
		want    map[target][]goarch
	}{
		{
			[]string{"bpf", "bpfel", "bpfeb"},
			map[target][]goarch{
				{"bpf", ""}:   nil,
				{"bpfel", ""}: clangArches["bpfel"],
				{"bpfeb", ""}: clangArches["bpfeb"],
			},
		},
		{
			[]string{"amd64", "386"},
			map[target][]goarch{
				{"bpfel", "x86"}: linuxArchesLE["x86"],
			},
		},
		{
			[]string{"amd64", "ppc64"},
			map[target][]goarch{
				{"bpfeb", "powerpc"}: linuxArchesBE["powerpc"],
				{"bpfel", "x86"}:     linuxArchesLE["x86"],
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
		{"no linux target", "mipsle"},
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
}

func TestGoarches(t *testing.T) {
	exe := goBin(t)

	for goarch := range targetByGoArch {
		t.Run(string(goarch), func(t *testing.T) {
			goEnv := exec.Command(exe, "env")
			goEnv.Env = []string{"GOROOT=/", "GOOS=linux", "GOARCH=" + string(goarch)}
			output, err := goEnv.CombinedOutput()
			qt.Assert(t, qt.IsNil(err), qt.Commentf("go output is:\n%s", string(output)))
		})
	}
}

func TestClangTargets(t *testing.T) {
	exe := goBin(t)

	clangTargets := map[string]struct{}{}
	for _, tgt := range targetByGoArch {
		clangTargets[tgt.clang] = struct{}{}
	}

	for target := range clangTargets {
		for _, env := range []string{"GOOS", "GOARCH"} {
			env += "=" + target
			t.Run(env, func(t *testing.T) {
				goEnv := exec.Command(exe, "env")
				goEnv.Env = []string{"GOROOT=/", env}
				output, err := goEnv.CombinedOutput()
				t.Log("go output is:", string(output))
				qt.Assert(t, qt.IsNotNil(err), qt.Commentf("No clang target should be a valid build constraint"))
			})
		}

	}
}

func clangBin(t *testing.T) string {
	t.Helper()

	if testing.Short() {
		t.Skip("Not compiling with -short")
	}

	// Use a floating clang version for local development, but allow CI to run
	// against oldest supported clang.
	clang := "clang"
	if minVersion := os.Getenv("CI_MIN_CLANG_VERSION"); minVersion != "" {
		clang = fmt.Sprintf("clang-%s", minVersion)
	}

	t.Log("Testing against", clang)
	return clang
}

func goBin(t *testing.T) string {
	t.Helper()

	exe, err := exec.LookPath("go")
	if errors.Is(err, exec.ErrNotFound) {
		t.Skip("go binary is not in PATH")
	}
	qt.Assert(t, qt.IsNil(err))

	return exe
}
