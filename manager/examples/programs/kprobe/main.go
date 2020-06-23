package main

import (
	"github.com/sirupsen/logrus"

	"github.com/DataDog/ebpf/manager"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			UID: "MyVFSMkdir",
			Section: "kprobe/vfs_mkdir",
		},
		&manager.Probe{
			UID: "", // UID is needed only if there are multiple instances of your program (after using
					 // m.CloneProgram for example), or if multiple programs with the exact same section are attaching
					 // at the exact same hook point (using m.AddHook for example, or simply because another manager
					 // on the system is planning on hooking there).
			Section:         "kretprobe/mkdirat",
			SyscallFuncName: "mkdirat",
			KProbeMaxActive: 100,
		},
	},
}

func main() {
	// Initialize the manager
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	// Close manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
