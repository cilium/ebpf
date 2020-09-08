package main

import (
	"fmt"
	"os"
	"os/signal"

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
			Section: "kprobe/utimes_common",
			MatchFuncName: "utimes_common",
			Optional: true,
		},
		&manager.Probe{
			Section: "kprobe/vfs_opennnnnn",
			Optional: true,
		},
		&manager.Probe{
			Section: "kprobe/exclude",
		},
	},
}

func main() {
	// Initialize the manager
	options := manager.Options{
		ActivatedProbes: []manager.ProbesSelector{
			manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:     "MyVFSMkdir",
					Section: "kprobe/vfs_mkdir",
				},
			},
			manager.OneOf{
				Selectors: []manager.ProbesSelector{
					manager.ProbeSelector{
						ProbeIdentificationPair: manager.ProbeIdentificationPair{
							Section: "kprobe/utimes_common",
						},
					},
					manager.ProbeSelector{
						ProbeIdentificationPair: manager.ProbeIdentificationPair{
							Section: "kprobe/vfs_opennnnnn",
						},
					},
				},
			},
			manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					Section: "kprobe/exclude",
				},
			},
		},
		ExcludedSections: []string{
			"kprobe/exclude",
		},
	}
	if err := m.InitWithOptions(recoverAssets(), options); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started")
	logrus.Println("=> Cmd+C to exit")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		logrus.Error(err)
	}

	wait()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
