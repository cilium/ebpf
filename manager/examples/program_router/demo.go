package main

import (
	"github.com/sirupsen/logrus"
	"time"

	"github.com/DataDog/ebpf/manager"
)

func demoTailCall() error {
	logrus.Println("generating some traffic to show what happens when the tail call is not set up ...")
	trigger()
	time.Sleep(1*time.Second)

	// prepare tail call
	route := manager.TailCallRoute{
		ProgArrayName: "tc_prog_array",
		Key: uint32(1),
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			Section: "classifier/two",
		},
	}

	// Map programs
	if err := m.UpdateTailCallRoutes(route); err != nil {
		return err
	}
	logrus.Println("generating some traffic to show what happens when the tail call is set up ...")
	trigger()
	return nil
}
