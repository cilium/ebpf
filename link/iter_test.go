//go:build !windows

package link

import (
	"io"
	"os"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestIterInfo(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "bpf_map iter")

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceIter, "bpf_map")

	it, err := AttachIter(IterOptions{Program: prog})
	qt.Assert(t, qt.IsNil(err))
	defer it.Close()

	info, err := it.Info()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(IterType, info.Type))
	iterInfo := info.Iter()
	qt.Assert(t, qt.Equals(iterInfo.TargetName, "bpf_map"))
}

func TestIter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "bpf_map iter")

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceIter, "bpf_map")

	it, err := AttachIter(IterOptions{
		Program: prog,
	})
	if err != nil {
		t.Fatal("Can't create iter:", err)
	}

	file, err := it.Open()
	if err != nil {
		t.Fatal("Can't open iter instance:", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	if len(contents) != 0 {
		t.Error("Non-empty output from no-op iterator:", string(contents))
	}

	testLink(t, it, prog)
}

func TestIterMapElements(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "bpf_map_elem iter")

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceIter, "bpf_map_elem")

	arr, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer arr.Close()

	it, err := AttachIter(IterOptions{
		Program: prog,
		Map:     arr,
	})
	if err != nil {
		t.Fatal("Can't create iter:", err)
	}
	defer it.Close()

	file, err := it.Open()
	if err != nil {
		t.Fatal("Can't open iter instance:", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	if len(contents) != 0 {
		t.Error("Non-empty output from no-op iterator:", string(contents))
	}
}

func TestUDPIter(t *testing.T) {
	// Introduced by 5788b3a07fc5 ("net: bpf: Implement bpf iterator for udp")
	testutils.SkipOnOldKernel(t, "5.9", "udp iter")

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceIter, "udp")

	it, err := AttachIter(IterOptions{
		Program: prog,
	})
	if err != nil {
		t.Fatal("Can't create iter:", err)
	}

	file, err := it.Open()
	if err != nil {
		t.Fatal("Can't open iter instance:", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	if len(contents) != 0 {
		t.Error("Non-empty output from no-op iterator:", string(contents))
	}

	testLink(t, it, prog)
}

func TestIterCgroup(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.1", "cgroup iter")

	prog := mustLoadProgram(t, ebpf.Tracing, ebpf.AttachTraceIter, "cgroup")
	cgroup := testutils.CreateCgroup(t)

	for _, tc := range []struct {
		name       string
		order      CgroupIterOrder
		minVersion string
	}{
		{"self", CgroupIterSelfOnly, "6.1"},
		{"pre", CgroupIterDescendantsPre, "6.1"},
		{"post", CgroupIterDescendantsPost, "6.1"},
		{"up", CgroupIterAncestorsUp, "6.1"},
		{"children", CgroupIterChildren, "7.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.SkipOnOldKernel(t, tc.minVersion, tc.name)
			it, err := AttachIter(IterOptions{
				Program: prog,
				Cgroup:  &CgroupIterOptions{Order: tc.order, Path: cgroup.Name()},
			})
			qt.Assert(t, qt.IsNil(err))
			defer it.Close()

			file, err := it.Open()
			qt.Assert(t, qt.IsNil(err))
			defer file.Close()

			contents, err := io.ReadAll(file)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.HasLen(contents, 0))
		})
	}

	it, err := AttachIter(IterOptions{
		Program: prog,
		Cgroup: &CgroupIterOptions{
			Order: CgroupIterSelfOnly,
			ID:    testutils.GetCgroupIno(t, cgroup),
		},
	})
	qt.Assert(t, qt.IsNil(err))
	defer it.Close()

	testLink(t, it, prog)
}

func TestIterTask(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "task iter")

	// Task iterator programs are invoked once for every visited task, and a
	// final time with a NULL task. This one writes a byte to the iterator's
	// output for each task, so the number of bytes read from the iterator is
	// the number of tasks visited.
	//
	// The context in r1 points to:
	//
	//	struct bpf_iter__task {
	//		struct bpf_iter_meta *meta; // offset 0, meta->seq is at offset 0
	//		struct task_struct *task;   // offset 8
	//	};
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachTraceIter,
		AttachTo:   "task",
		License:    "GPL",
		Instructions: asm.Instructions{
			// task will be null if iteration is done.
			//
			// if (!ctx->task) goto exit;
			asm.LoadMem(asm.R2, asm.R1, 8, asm.DWord),
			asm.JEq.Imm(asm.R2, 0, "exit"),

			// Dereference R1 twice to step through the first fields (pointers)
			// in ctx and meta respectively.
			//
			// bpf_seq_write(struct seq_file *m, const void *data, u32 len):
			// m = ctx->meta->seq
			asm.LoadMem(asm.R1, asm.R1, 0, asm.DWord),
			asm.LoadMem(asm.R1, asm.R1, 0, asm.DWord),
			// data = a zeroed stack slot
			asm.StoreImm(asm.RFP, -8, 0, asm.DWord),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -8),
			// len = 1
			asm.Mov.Imm(asm.R3, 1),
			asm.FnSeqWrite.Call(),

			// exit: return 0;
			asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
			asm.Return(),
		},
	})
	qt.Assert(t, qt.IsNil(err))
	defer prog.Close()

	numTasks := func(t *testing.T, opts *TaskIterOptions) int {
		t.Helper()

		it, err := AttachIter(IterOptions{Program: prog, Task: opts})
		testutils.SkipIfNotSupported(t, err)
		qt.Assert(t, qt.IsNil(err))
		defer it.Close()

		file, err := it.Open()
		qt.Assert(t, qt.IsNil(err))
		defer file.Close()

		contents, err := io.ReadAll(file)
		qt.Assert(t, qt.IsNil(err))
		return len(contents)
	}

	pid := uint32(os.Getpid())

	t.Run("all", func(t *testing.T) {
		tasks := numTasks(t, &TaskIterOptions{})
		qt.Assert(t, qt.IsTrue(tasks > 1))
	})

	t.Run("tid", func(t *testing.T) {
		// Older kernels silently ignore TID instead of rejecting it.
		testutils.SkipOnOldKernel(t, "6.1", "task iter TID")

		// The main thread's TID is the PID.
		qt.Assert(t, qt.Equals(numTasks(t, &TaskIterOptions{TID: pid}), 1))
	})

	t.Run("pid", func(t *testing.T) {
		// Kernels before 6.1 reject PID with E2BIG, skipping the subtest.
		threads := numTasks(t, &TaskIterOptions{PID: pid})
		all := numTasks(t, &TaskIterOptions{})

		// The Go runtime has several threads, the system has many more tasks.
		qt.Assert(t, qt.IsTrue(threads > 1))
		qt.Assert(t, qt.IsTrue(threads < all))
	})

	it, err := AttachIter(IterOptions{Program: prog, Task: &TaskIterOptions{}})
	qt.Assert(t, qt.IsNil(err))
	defer it.Close()

	testLink(t, it, prog)
}

func TestIterInput(t *testing.T) {
	// Program type that loads on all kernels. Not expected to link successfully.
	prog := mustLoadProgram(t, ebpf.SocketFilter, 0, "")

	// Program is required.
	_, err := AttachIter(IterOptions{})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// Map and Cgroup are mutually exclusive.
	_, err = AttachIter(IterOptions{
		Program: prog,
		Map:     &ebpf.Map{},
		Cgroup:  &CgroupIterOptions{Order: CgroupIterSelfOnly},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// Order is required.
	_, err = AttachIter(IterOptions{
		Program: prog,
		Cgroup:  &CgroupIterOptions{Path: "/"},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// Path and ID are mutually exclusive.
	_, err = AttachIter(IterOptions{
		Program: prog,
		Cgroup:  &CgroupIterOptions{Order: CgroupIterSelfOnly, Path: "/", ID: 1},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// Map and Task are mutually exclusive.
	_, err = AttachIter(IterOptions{
		Program: prog,
		Map:     &ebpf.Map{},
		Task:    &TaskIterOptions{},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// TID and PID are mutually exclusive.
	_, err = AttachIter(IterOptions{
		Program: prog,
		Task:    &TaskIterOptions{TID: 1, PID: 1},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))
}
