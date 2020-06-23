package main

import (
	"fmt"
	"github.com/DataDog/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/DataDog/ebpf/manager"
)

type TestData struct {
	Input uint32
	Output uint32
}

func (td TestData) String() string {
	return fmt.Sprintf("{ Input:%v Output:%v }", td.Input, td.Output)
}

var testDataKey = uint32(1)

var testData = []TestData{
	{2, 4},
	{10, 20},
	{42, 128},
	{42, 84},
}

func main() {
	// Initialize the manager
	var m = &manager.Manager{}
	if err := m.Init(recoverAssets()); err != nil {
		logrus.Fatal(err)
	}

	// Get map used to send tests
	testMap, found, err := m.GetMap("my_func_test_data")
	if !found || err != nil {
		logrus.Fatalf("couldn't retrieve my_func_test_data %v", err)
	}

	// Get xdp program used to trigger the tests
	testProgs, found, err := m.GetProgram(
		manager.ProbeIdentificationPair{
			Section: "xdp/my_func_test",
		},
	)
	if !found || err != nil {
		logrus.Fatalf("couldn't retrieve my_func_test %v", err)
	}
	testProg := testProgs[0]

	// Run test
	runtTest(testMap, testProg)

	// Run benchmark
	runtBenchmark(testMap, testProg)

	// Close manager
	if err := m.Stop(manager.CleanAll); err != nil {
		logrus.Fatal(err)
	}
}

func runtTest(testMap *ebpf.Map, testProg *ebpf.Program) {
	logrus.Println("Running tests ...")
	for _, data := range testData {
		// insert data
		testMap.Put(testDataKey, data)

		// Trigger test - (the 14 bytes is for the minimum packet size required to test an XDP program)
		outLen, _, err := testProg.Test(make([]byte, 14))
		if err != nil {
			logrus.Fatal(err)
		}
		if outLen == 0 {
			logrus.Printf("%v - PASS", data)
		} else {
			logrus.Printf("%v - FAIL", data)
		}
	}
}

func runtBenchmark(testMap *ebpf.Map, testProg *ebpf.Program) {
	logrus.Println("Running benchmark ...")
	for _, data := range testData {
		// insert data
		testMap.Put(testDataKey, data)

		// Trigger test
		outLen, duration, err := testProg.Benchmark(make([]byte, 14), 1000, nil)
		if err != nil {
			logrus.Fatal(err)
		}
		if outLen == 0 {
			logrus.Printf("%v - PASS (duration: %v)", data, duration)
		} else {
			logrus.Printf("%v - benchmark FAILED", data)
		}
	}
}
