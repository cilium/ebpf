package main

import (
	"github.com/sirupsen/logrus"

	"github.com/DataDog/ebpf/manager"
)

func demoClone() error {
	logrus.Println("CLONE DEMO")
	// Clone kprobe/vfs_open program, edit its constant and load a new probe. This will essentially create a new program
	// and you should see a new line in /sys/kernel/debug/tracing/kprobe_events.
	newProbe := manager.Probe{
		UID:     "MySeconHook",
		Section: "kprobe/vfs_mkdir",
	}

	mkdirCloneEditors := []manager.ConstantEditor{
		{
			Name:  "my_constant",
			Value: uint64(42),
			ProbeIdentificationPairs: []manager.ProbeIdentificationPair{
				newProbe.GetIdentificationPair(),
			},
		},
	}

	err := m.CloneProgram("MyFirstHook", newProbe, mkdirCloneEditors, nil)
	if err != nil {
		return err
	}

	return trigger()
}

func demoAddHook() error {
	logrus.Println("ADD HOOK DEMO")
	// Add a new hook point to the kprobe/vfs_mkdir program. The program was initially loaded but not attached. This will
	// not create a copy of the program, it will just add a new hook point. This can be donne multiple times.
	firstRmdir := manager.Probe{
		UID:     "FirstRmdir",
		Section: "kprobe/vfs_rmdir",
	}
	err := m.AddHook("", firstRmdir)
	if err != nil {
		logrus.Fatal(err)
	}

	secondRmdir := manager.Probe{
		UID:     "SecondRmdir",
		Section: "kprobe/vfs_rmdir",
	}
	err = m.AddHook("", secondRmdir)
	if err != nil {
		return err
	}

	if err = trigger(); err != nil {
		return err
	}

	logrus.Println("DETACH HOOK DEMO")

	// Detaching a hook point does not close the underlying eBPF program, which means that the other hook points are
	// still working
	err = m.DetachHook(secondRmdir.Section, secondRmdir.UID)
	if err != nil {
		return err
	}

	return trigger()
}
