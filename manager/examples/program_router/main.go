package main

import (
	"github.com/sirupsen/logrus"

	"github.com/DataDog/ebpf/manager"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			Section:          "classifier/one",
			Ifname:           "enp0s3", // change this to the interface index connected to the internet
			NetworkDirection: manager.Egress,
		},
	},
}

var m2 = &manager.Manager{
	Probes: []*manager.Probe{},
}

func main() {
	// Initialize the manager
	if err := m.Init(recoverAssets("/probe1.o")); err != nil {
		logrus.Fatal(err)
	}
	if err := m2.Init(recoverAssets("/probe2.o")); err != nil {
		logrus.Fatal(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}
	if err := m2.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	if err := demoTailCall(); err != nil {
		logrus.Error(err)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
	if err := m2.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}
