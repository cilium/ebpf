package main

import (
	"github.com/DataDog/ebpf/manager"
	"github.com/sirupsen/logrus"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			Section: "cgroup/skb/egress",
			CGroupPath: "/sys/fs/cgroup/unified",
		},
	},
}

func main() {
	// Initialize the manager
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Generate some network traffic to trigger the probe
	trigger()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}

