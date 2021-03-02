package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"

	goperf "github.com/elastic/go-perf"
	"github.com/rs/xid"
)

const (
	kProbesPath      string = "/sys/kernel/debug/tracing/events/kprobes/"
	kProbeEventsPath string = "/sys/kernel/debug/tracing/kprobe_events"
)

type KProbe struct {
	name    string
	syscall string
}

func New(syscall string) (*KProbe, error) {
	kp := KProbe{name: fmt.Sprintf("%s_%s", xid.New().String(), syscall), syscall: syscall}

	if err := appendToFile(kProbeEventsPath, kp.Descriptor()); err != nil {
		return nil, err
	}

	return &kp, nil
}

func (kp *KProbe) Attach(fd uint32) (func(), error) {
	var (
		closer       = func() {}
		attr         = &goperf.Attr{}
		configurator = kp.Configurator()
	)

	if err := configurator.Configure(attr); err != nil {
		return closer, err
	}

	runtime.LockOSThread()
	closer = func() { runtime.UnlockOSThread() }

	perfEv, err := goperf.Open(attr, goperf.CallingThread, goperf.AnyCPU, nil)
	if err != nil {
		return closer, err
	}
	closer = func() {
		perfEv.Close()
		runtime.UnlockOSThread()
	}

	if err := perfEv.Enable(); err != nil {
		return closer, err
	}

	err = perfEv.SetBPF(fd)
	return func() {
		_ = perfEv.Disable()
		perfEv.Close()
	}, err
}

func (kp *KProbe) Descriptor() string {
	return fmt.Sprintf("p:kprobes/%s %s", kp.name, kp.syscall)
}

type configuratorFunc func(attr *goperf.Attr) error

func (cf configuratorFunc) Configure(attr *goperf.Attr) error { return cf(attr) }
func (kp *KProbe) Configurator() goperf.Configurator {
	return configuratorFunc(func(attr *goperf.Attr) error {
		kpID, err := kp.ID()
		if err != nil {
			return err
		}
		attr.Label = kp.name
		attr.Type = goperf.TracepointEvent
		attr.Config = kpID
		return nil
	})
}

func (kp *KProbe) ID() (uint64, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("%s%s/id", kProbesPath, kp.name))
	if err != nil {
		return 0, err
	}
	tid := strings.TrimSuffix(string(data), "\n")
	return strconv.ParseUint(tid, 10, 64)
}

func (kp *KProbe) Close() error {
	return appendToFile(kProbeEventsPath, fmt.Sprintf("-:kprobes/%s", kp.name))
}

func appendToFile(path string, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(content); err != nil {
		return err
	}
	return nil
}
