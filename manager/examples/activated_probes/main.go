package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"

	"github.com/DataDog/ebpf/manager"
)

var m1 = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			UID: "MyVFSMkdir1",
			Section: "kprobe/vfs_mkdir",
		},
		&manager.Probe{
			Section: "kprobe/utimes_common",
			MatchFuncName: "utimes_common",
		},
		&manager.Probe{
			Section: "kprobe/vfs_opennnnnn",
		},
		&manager.Probe{
			Section: "kprobe/exclude",
		},
	},
}

var options1 = manager.Options{
	ActivatedProbes: []manager.ProbesSelector{
		&manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:     "MyVFSMkdir1",
				Section: "kprobe/vfs_mkdir",
			},
		},
		&manager.AllOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						UID:     "MyVFSMkdir1",
						Section: "kprobe/vfs_mkdir",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						Section: "kprobe/utimes_common",
					},
				},
			},
		},
		&manager.OneOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						Section: "kprobe/utimes_common",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						Section: "kprobe/vfs_opennnnnn",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						Section: "kprobe/exclude",
					},
				},
			},
		},
	},
	ExcludedSections: []string{
		"kprobe/exclude2",
	},
}

var m2 = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			UID: "MyVFSMkdir2",
			Section: "kprobe/vfs_mkdir",
		},
		&manager.Probe{
			Section: "kprobe/utimes_common",
			MatchFuncName: "utimes_common",
		},
		&manager.Probe{
			Section: "kprobe/vfs_opennnnnn",
		},
		&manager.Probe{
			Section: "kprobe/exclude",
		},
	},
}

var options2 = manager.Options{
	ActivatedProbes: []manager.ProbesSelector{
		&manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:     "MyVFSMkdir2",
				Section: "kprobe/vfs_mkdir",
			},
		},
		&manager.AllOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						Section: "kprobe/vfs_opennnnnn",
					},
				},
			},
		},
		&manager.OneOf{
			Selectors: []manager.ProbesSelector{
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						Section: "kprobe/vfs_opennnnnn",
					},
				},
				&manager.ProbeSelector{
					ProbeIdentificationPair: manager.ProbeIdentificationPair{
						Section: "kprobe/exclude",
					},
				},
			},
		},
	},
	ExcludedSections: []string{
		"kprobe/exclude",
	},
}

var m3 = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			UID: "MyVFSMkdir2",
			Section: "kprobe/vfs_mkdir",
		},
		&manager.Probe{
			Section: "kprobe/utimes_common",
			MatchFuncName: "utimes_common",
		},
		&manager.Probe{
			Section: "kprobe/vfs_opennnnnn",
		},
		&manager.Probe{
			Section: "kprobe/exclude",
		},
	},
}

func main() {
	// Initialize the managers
	if err := m1.InitWithOptions(recoverAssets(), options1); err != nil {
		logrus.Fatal(err)
	}

	newID := manager.ProbeIdentificationPair{Section: "kprobe/exclude2"}
	if err := m1.RenameProbeIdentificationPair(manager.ProbeIdentificationPair{Section: "kprobe/exclude"}, newID); err != nil {
		logrus.Fatal(err)
	}

	_, ok := m1.GetProbe(newID)
	if !ok {
		logrus.Fatal("EditProbeIdentificationPair failed")
	}

	// Start m1
	if err := m1.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("m1 successfully started")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	if err := m1.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("=> Cmd+C to continue")
	wait()

	logrus.Println("moving on to m2 (an error is expected)")
	// Initialize the managers
	if err := m2.InitWithOptions(recoverAssets(), options2); err != nil {
		logrus.Fatal(err)
	}

	// Start m2
	if err := m2.Start(); err != nil {
		logrus.Error(err)
	}

	logrus.Println("=> Cmd+C to continue")
	wait()

	logrus.Println("moving on to m3 (an error is expected)")
	if err := m3.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start m3
	if err := m3.Start(); err != nil {
		logrus.Error(err)
	}
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
