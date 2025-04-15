package btf

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestLoadKernelSpec(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/vmlinux not present")
	}

	_, err := LoadKernelSpec()
	if err != nil {
		t.Fatal("Can't load kernel spec:", err)
	}
}

func TestLoadKernelModuleSpec(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/btf_testmod"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/btf_testmod not present")
	}

	_, err := LoadKernelModuleSpec("btf_testmod")
	qt.Assert(t, qt.IsNil(err))
}

func TestLoadKernelSpecWithOpts(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/vmlinux not present")
	}

	kernelBTF.kernel = nil

	opts := &SpecOptions{
		TypeNames: map[string]struct{}{
			"task_struct": {},
			"pt_regs":     {},
			"socket":      {},
		},
	}

	spec1, err := LoadKernelSpecWithOptions(opts)
	if err != nil {
		t.Fatal("Can't load kernel spec:", err)
	}

	spec2, err := LoadKernelSpecWithOptions(opts)
	if err != nil {
		t.Fatal("Can't load kernel spec:", err)
	}

	qt.Assert(t, qt.Equals(len(spec1.imm.types), len(spec2.imm.types)))
	qt.Assert(t, qt.Equals(len(spec1.imm.typeIDs), len(spec2.imm.typeIDs)))
	qt.Assert(t, qt.DeepEquals(spec1.imm.namedTypes, spec2.imm.namedTypes))
}

func TestLoadKernelSpecWithMoreOpts(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/vmlinux not present")
	}

	opts1 := &SpecOptions{
		TypeNames: map[string]struct{}{
			"pt_regs": {},
		},
	}

	kernelBTF.kernel = nil

	spec1, err := LoadKernelSpecWithOptions(opts1)
	if err != nil {
		t.Fatal("Can't load kernel spec:", err)
	}

	opts2 := &SpecOptions{
		TypeNames: map[string]struct{}{
			"task_struct": {},
			"socket":      {},
		},
	}

	spec2, err := LoadKernelSpecWithOptions(opts2)
	if err != nil {
		t.Fatal("Can't load kernel spec:", err)
	}

	for typeName := range opts1.TypeNames {
		contains := false
		for _, t := range spec1.imm.types {
			if t.TypeName() == typeName {
				contains = true
				break
			}
		}
		qt.Assert(t, qt.IsTrue(contains))

		contains = false
		for _, t := range spec2.imm.types {
			if t.TypeName() == typeName {
				contains = true
				break
			}
		}
		qt.Assert(t, qt.IsTrue(contains))
	}

	for typeName := range opts2.TypeNames {
		contains := false
		for _, t := range spec1.imm.types {
			if t.TypeName() == typeName {
				contains = true
				break
			}
		}
		qt.Assert(t, qt.IsFalse(contains))

		contains = false
		for _, t := range spec2.imm.types {
			if t.TypeName() == typeName {
				contains = true
				break
			}
		}
		// pt_regs is included in here indirectly
		qt.Assert(t, qt.IsTrue(contains))
	}
}
