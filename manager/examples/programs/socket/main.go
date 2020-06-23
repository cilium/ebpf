package main

import (
	"github.com/sirupsen/logrus"

	"github.com/DataDog/ebpf/manager"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			Section: "socket/sock_filter",
		},
	},
}

func main() {
	// Create a socket pair that will be used to trigger the socket filter
	sockPair, err := newSocketPair()
	if err != nil {
		logrus.Fatal(err)
	}

	// Set the socket file descriptor on which the socket filter should trigger
	m.Probes[0].SocketFD = sockPair[0]

	// Initialize the manager
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Start manager
	if err := m.Start(); err != nil {
		logrus.Fatal(err)
	}

	logrus.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Send a message through the socket pair to trigger the probe
	if err := trigger(sockPair); err != nil {
		logrus.Error(err)
	}

	// Close manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}

