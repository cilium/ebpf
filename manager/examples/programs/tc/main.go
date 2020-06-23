package main

import (
	"github.com/DataDog/ebpf/manager"
	"github.com/sirupsen/logrus"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			Section: "classifier/egress",
			Ifname: "enp0s3", // change this to the interface index connected to the internet
			NetworkDirection: manager.Egress,
		},
		&manager.Probe{
			Section: "classifier/ingress",
			Ifname: "enp0s3", // change this to the interface index connected to the internet
			NetworkDirection: manager.Ingress,
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

	// Generate some network traffic to trigger the probe
	trigger()

	// Close manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}

