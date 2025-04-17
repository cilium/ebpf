//go:build !windows

package gen

import (
	"errors"
	"os/exec"
	"slices"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestCollectTargets(t *testing.T) {
	clangArches := make(map[string][]GoArch)
	linuxArchesLE := make(map[string][]GoArch)
	linuxArchesBE := make(map[string][]GoArch)
	for arch, archTarget := range targetsByGoArch {
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

	nativeTarget, nativeArches, err := FindTarget("native")
	qt.Assert(t, qt.IsNil(err))

	tests := []struct {
		short  string
		target Target
		arches GoArches
	}{
		{
			"bpf",
			Target{"bpf", "", ""},
			nil,
		},
		{
			"bpfel",
			Target{"bpfel", "", ""},
			clangArches["bpfel"],
		},
		{
			"bpfeb",
			Target{"bpfeb", "", ""},
			clangArches["bpfeb"],
		},
		{
			"amd64",
			Target{"bpfel", "x86", ""},
			linuxArchesLE["x86"],
		},
		{
			"386",
			Target{"bpfel", "x86", ""},
			linuxArchesLE["x86"],
		},
		{
			"ppc64",
			Target{"bpfeb", "powerpc", ""},
			linuxArchesBE["powerpc"],
		},
		{
			"native",
			nativeTarget,
			nativeArches,
		},
	}

	for _, test := range tests {
		t.Run(test.short, func(t *testing.T) {
			target, arches, err := FindTarget(test.short)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(target, test.target))
			qt.Assert(t, qt.DeepEquals(arches, test.arches))
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
			_, _, err := FindTarget(test.target)
			if err == nil {
				t.Fatal("Function did not return an error")
			}
			t.Log("Error message:", err)
		})
	}
}

func TestGoarches(t *testing.T) {
	exe := goBin(t)

	for GoArch, tgt := range targetsByGoArch {
		t.Run(string(GoArch), func(t *testing.T) {
			goOS := "linux"
			if tgt.goos != "" {
				goOS = tgt.goos
			}
			goEnv := exec.Command(exe, "env")
			goEnv.Env = []string{"GOROOT=/", "GOOS=" + string(goOS), "GOARCH=" + string(GoArch)}
			output, err := goEnv.CombinedOutput()
			qt.Assert(t, qt.IsNil(err), qt.Commentf("go output is:\n%s", string(output)))
		})
	}
}

func TestClangTargets(t *testing.T) {
	exe := goBin(t)

	clangTargets := map[string]struct{}{}
	for _, tgt := range targetsByGoArch {
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

func goBin(t *testing.T) string {
	t.Helper()

	exe, err := exec.LookPath("go")
	if errors.Is(err, exec.ErrNotFound) {
		t.Skip("go binary is not in PATH")
	}
	qt.Assert(t, qt.IsNil(err))

	return exe
}
